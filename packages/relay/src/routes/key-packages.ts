import type { FastifyInstance } from 'fastify';
import {
  addApprovalContent,
  bytesEqual,
  CIPHERSUITE_V1,
  decodeKeyPackageMessage,
  keyPackageRef,
  SignatureLabel,
  toBase64,
  verifyWithLabel,
} from '@agent-bridge/protocol';
import { lockLiveDevice, nowSeconds, requireDevice } from '../auth.ts';
import type { RelayContext } from '../context.ts';
import { bytes, withTransaction } from '../db.ts';
import type { Queryable } from '../db.ts';
import { deliver } from '../deliver.ts';
import { badRequest, conflict, forbidden, notFound, RelayError, tooManyRequests, unauthorized } from '../errors.ts';
import { approvalIdSchema, base64Schema, decodeBase64Field, parseUuid, uniqueViolation, uuidSchema } from '../validate.ts';
import { loadMembership } from './topics.ts';

const MAX_KEY_PACKAGE_BYTES = 16 * 1024;

async function unclaimedCount(db: Queryable, deviceId: string, now: Date): Promise<number> {
  const { rows } = await db.query<{ n: number }>(
    'SELECT count(*)::int AS n FROM key_packages WHERE device_id = $1 AND claimed_at IS NULL AND expires_at > $2',
    [deviceId, now],
  );
  return rows[0]!.n;
}

interface ClaimBody {
  topic_id: string;
  approval_id: string;
  expires_at: number;
  approval: string;
}

export function keyPackageRoutes(app: FastifyInstance, ctx: RelayContext): void {
  const auth = { onRequest: requireDevice(ctx) };

  app.post<{ Body: { key_packages: string[] } }>(
    '/v1/key-packages',
    {
      ...auth,
      schema: {
        body: {
          type: 'object',
          required: ['key_packages'],
          additionalProperties: false,
          properties: {
            key_packages: { type: 'array', minItems: 1, maxItems: 100, items: base64Schema(MAX_KEY_PACKAGE_BYTES) },
          },
        },
      },
    },
    async (request) => {
      const device = request.device;
      const now = ctx.now();
      const expiresAt = new Date(now.getTime() + ctx.config.keyPackageTtlDays * 86_400_000);

      const parsed = request.body.key_packages.map((encoded, i) => {
        const message = decodeBase64Field(`key_packages[${i}]`, encoded);
        let summary;
        try {
          summary = decodeKeyPackageMessage(message);
        } catch {
          throw badRequest('invalid_key_package', `key_packages[${i}] is not an MLS KeyPackage`);
        }
        if (summary.cipherSuite !== CIPHERSUITE_V1) {
          throw badRequest('unsupported_ciphersuite', `key_packages[${i}] must use cipher suite ${CIPHERSUITE_V1}`);
        }
        if (!bytesEqual(summary.signatureKey, device.signatureKey)) {
          throw badRequest('key_package_not_yours', `key_packages[${i}] is not signed by this device's key`);
        }
        return { message, ref: keyPackageRef(summary.keyPackage), cipherSuite: summary.cipherSuite };
      });

      return withTransaction(ctx.pool, async (db) => {
        if (!(await lockLiveDevice(db, device.id))) throw unauthorized('device unknown or revoked');
        let room = ctx.config.maxUnclaimedKeyPackages - (await unclaimedCount(db, device.id, now));
        if (room <= 0) throw tooManyRequests('too many unclaimed KeyPackages');
        let accepted = 0;
        for (const kp of parsed) {
          if (room <= 0) break;
          const result = await db.query(
            `INSERT INTO key_packages (device_id, ciphersuite, key_package_ref, key_package, expires_at)
             VALUES ($1, $2, $3, $4, $5) ON CONFLICT (key_package_ref) DO NOTHING`,
            [device.id, kp.cipherSuite, kp.ref, kp.message, expiresAt],
          );
          const inserted = result.rowCount ?? 0;
          accepted += inserted;
          room -= inserted;
        }
        return { accepted, unclaimed: await unclaimedCount(db, device.id, now) };
      });
    },
  );

  app.get('/v1/key-packages/count', auth, async (request) => ({
    unclaimed: await unclaimedCount(ctx.pool, request.device.id, ctx.now()),
  }));

  // The topic owner claims one of the invitee device's KeyPackages, presenting the add approval.
  app.post<{ Params: { deviceId: string }; Body: ClaimBody }>(
    '/v1/devices/:deviceId/key-packages/claim',
    {
      ...auth,
      schema: {
        body: {
          type: 'object',
          required: ['topic_id', 'approval_id', 'expires_at', 'approval'],
          additionalProperties: false,
          properties: {
            topic_id: uuidSchema,
            approval_id: approvalIdSchema,
            expires_at: { type: 'integer', minimum: 0 },
            approval: base64Schema(64),
          },
        },
      },
    },
    async (request) => {
      const caller = request.device;
      const targetId = parseUuid('deviceId', request.params.deviceId);
      const topicId = parseUuid('topic_id', request.body.topic_id);
      const { approval_id: approvalId, expires_at: approvalExpiresAt } = request.body;
      const approval = decodeBase64Field('approval', request.body.approval, 64);
      const now = ctx.now();

      const result = await withTransaction(ctx.pool, async (db) => {
        // One claimer at a time, so the cap and the "same approval returns the same package" check are atomic.
        if (!(await lockLiveDevice(db, caller.id))) throw unauthorized('device unknown or revoked');

        const membership = await loadMembership(db, topicId, caller.id);
        if (!membership) throw notFound();
        if (membership.owner_account !== caller.accountId) {
          throw forbidden('not_topic_owner', 'only the topic owner can claim KeyPackages for an add');
        }

        const { rows: targets } = await db.query<{ signature_pubkey: Buffer; identity_pubkey: Buffer }>(
          `SELECT d.signature_pubkey, a.identity_pubkey FROM devices d JOIN accounts a ON a.id = d.account_id
            WHERE d.id = $1 AND d.revoked_at IS NULL`,
          [targetId],
        );
        const target = targets[0];
        if (!target) throw notFound('device unknown or revoked');

        const content = addApprovalContent({
          topicId,
          approvalId,
          inviteeIdentityKey: bytes(target.identity_pubkey),
          inviteeDeviceKey: bytes(target.signature_pubkey),
          role: 'member',
          expiresAt: approvalExpiresAt,
        });
        if (!verifyWithLabel(caller.identityKey, SignatureLabel.add, content, approval)) {
          throw forbidden('invalid_approval', 'add approval does not verify under the topic owner identity key');
        }
        if (approvalExpiresAt <= nowSeconds(ctx)) throw badRequest('approval_expired', 'add approval has expired');

        const used = await db.query('SELECT 1 FROM membership_changes WHERE topic_id = $1 AND approval_id = $2', [
          topicId,
          approvalId,
        ]);
        if (used.rowCount) throw conflict('approval_used', 'this approval was already used in a commit');

        // A retry of the same approval on the same topic returns the same KeyPackage.
        // approval_id is only unique per topic, so the topic is part of the key.
        const previous = await db.query<{ key_package: Buffer }>(
          `SELECT key_package FROM key_packages
            WHERE device_id = $1 AND claimed_by = $2 AND claim_topic_id = $3 AND claim_approval_id = $4`,
          [targetId, caller.id, topicId, approvalId],
        );
        if (previous.rows[0]) return { keyPackage: bytes(previous.rows[0].key_package), remaining: null };

        const recent = await db.query<{ n: number }>(
          "SELECT count(*)::int AS n FROM key_packages WHERE claimed_by = $1 AND claimed_at > $2::timestamptz - interval '1 hour'",
          [caller.id, now],
        );
        if (recent.rows[0]!.n >= ctx.config.keyPackageClaimsPerHour) {
          throw tooManyRequests('too many KeyPackage claims in the last hour');
        }

        // The device lock serializes one claimer. The unique index is the backstop
        // if two claimers ever present the same (topic, approval).
        await db.query('SAVEPOINT claim_kp');
        let row: { key_package: Buffer } | undefined;
        try {
          const claimed = await db.query<{ key_package: Buffer }>(
            `UPDATE key_packages SET claimed_at = $3, claimed_by = $2, claim_approval_id = $4, claim_topic_id = $5
              WHERE id = (SELECT id FROM key_packages
                           WHERE device_id = $1 AND claimed_at IS NULL AND expires_at > $3
                           ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED)
              RETURNING key_package`,
            [targetId, caller.id, now, approvalId, topicId],
          );
          row = claimed.rows[0];
        } catch (err) {
          if (uniqueViolation(err) !== 'key_packages_claim_topic_approval') throw err;
          await db.query('ROLLBACK TO SAVEPOINT claim_kp');
          const again = await db.query<{ key_package: Buffer }>(
            'SELECT key_package FROM key_packages WHERE claim_topic_id = $1 AND claim_approval_id = $2',
            [topicId, approvalId],
          );
          row = again.rows[0];
        }
        if (!row) throw new RelayError(404, 'no_key_package', 'the device has no unclaimed KeyPackages; retry later');
        await db.query("INSERT INTO audit_log (account_id, device_id, topic_id, action) VALUES ($1, $2, $3, 'claim_kp')", [
          caller.accountId,
          caller.id,
          topicId,
        ]);
        return { keyPackage: bytes(row.key_package), remaining: await unclaimedCount(db, targetId, now) };
      });

      if (result.remaining !== null && result.remaining < ctx.config.keyPackageLowWatermark) {
        await deliver(ctx, [targetId], { type: 'key_packages_low', count: result.remaining });
      }
      return { key_package: toBase64(result.keyPackage) };
    },
  );
}
