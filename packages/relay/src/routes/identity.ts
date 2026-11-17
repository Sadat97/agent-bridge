import { randomBytes } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import {
  bytesEqual,
  relayAuthContent,
  SignatureLabel,
  toBase64,
  verifyDeviceCert,
  verifyWithLabel,
} from '@agent-bridge/protocol';
import { issueAccessToken, loadDevice, lockLiveDevice, nowSeconds, requireDevice } from '../auth.ts';
import type { RelayContext } from '../context.ts';
import { bytes, withTransaction } from '../db.ts';
import type { Queryable } from '../db.ts';
import { badRequest, conflict, notFound, tooManyRequests, unauthorized } from '../errors.ts';
import { base64Schema, decodeBase64Field, parseUuid, uniqueViolation, uuidSchema } from '../validate.ts';

async function deleteExpiredChallenges(db: Queryable, now: Date): Promise<void> {
  await db.query('DELETE FROM auth_challenges WHERE expires_at <= $1', [now]);
}

interface RegisterBody {
  handle: string;
  identity_pubkey: string;
  device: { id: string; signature_pubkey: string; cert: string };
}

export function identityRoutes(app: FastifyInstance, ctx: RelayContext): void {
  // Register a person: handle, identity key, and their first device with its certificate.
  app.post<{ Body: RegisterBody }>(
    '/v1/accounts',
    {
      schema: {
        body: {
          type: 'object',
          required: ['handle', 'identity_pubkey', 'device'],
          additionalProperties: false,
          properties: {
            handle: { type: 'string', pattern: '^[a-z0-9][a-z0-9_-]{1,31}$' },
            identity_pubkey: base64Schema(32),
            device: {
              type: 'object',
              required: ['id', 'signature_pubkey', 'cert'],
              additionalProperties: false,
              properties: { id: uuidSchema, signature_pubkey: base64Schema(32), cert: base64Schema(1024) },
            },
          },
        },
      },
    },
    async (request, reply) => {
      const { handle, device } = request.body;
      const identityKey = decodeBase64Field('identity_pubkey', request.body.identity_pubkey, 32);
      const deviceId = parseUuid('device.id', device.id);
      const signatureKey = decodeBase64Field('device.signature_pubkey', device.signature_pubkey, 32);
      const cert = decodeBase64Field('device.cert', device.cert);

      const certified = verifyDeviceCert(cert, identityKey);
      if (
        !certified ||
        certified.handle !== handle ||
        certified.deviceId !== deviceId ||
        !bytesEqual(certified.signatureKey, signatureKey)
      ) {
        throw badRequest('invalid_device_cert', 'device certificate does not verify for this handle, device, and key');
      }

      try {
        const accountId = await withTransaction(ctx.pool, async (db) => {
          const { rows } = await db.query<{ id: string }>(
            'INSERT INTO accounts (handle, identity_pubkey) VALUES ($1, $2) RETURNING id',
            [handle, identityKey],
          );
          const id = rows[0]!.id;
          await db.query(
            'INSERT INTO devices (id, account_id, signature_pubkey, device_cert) VALUES ($1, $2, $3, $4)',
            [deviceId, id, signatureKey, cert],
          );
          await db.query("INSERT INTO audit_log (account_id, device_id, action) VALUES ($1, $2, 'register')", [
            id,
            deviceId,
          ]);
          return id;
        });
        return reply.code(201).send({ account_id: accountId, handle, device_id: deviceId });
      } catch (err) {
        const constraint = uniqueViolation(err);
        if (constraint === 'accounts_handle_key') throw conflict('handle_taken', 'handle is already registered');
        if (constraint !== null) throw conflict('device_exists', 'device id or key is already registered');
        throw err;
      }
    },
  );

  // Public key material for a handle, so bridges can pin keys and show fingerprints.
  app.get<{ Params: { handle: string } }>(
    '/v1/accounts/:handle',
    { onRequest: requireDevice(ctx) },
    async (request) => {
      const { rows } = await ctx.pool.query<{
        handle: string;
        identity_pubkey: Buffer;
        device_id: string | null;
        signature_pubkey: Buffer | null;
        device_cert: Buffer | null;
        revoked_at: Date | null;
      }>(
        `SELECT a.handle, a.identity_pubkey, d.id AS device_id, d.signature_pubkey, d.device_cert, d.revoked_at
           FROM accounts a LEFT JOIN devices d ON d.account_id = a.id
          WHERE a.handle = $1
          ORDER BY d.created_at`,
        [request.params.handle],
      );
      const first = rows[0];
      if (!first) throw notFound('no such handle');
      return {
        handle: first.handle,
        identity_pubkey: toBase64(bytes(first.identity_pubkey)),
        devices: rows
          .filter((r) => r.device_id !== null)
          .map((r) => ({
            device_id: r.device_id,
            signature_pubkey: toBase64(bytes(r.signature_pubkey!)),
            cert: toBase64(bytes(r.device_cert!)),
            revoked: r.revoked_at !== null,
          })),
      };
    },
  );

  app.post<{ Body: { device_id: string } }>(
    '/v1/auth/challenge',
    {
      schema: {
        body: {
          type: 'object',
          required: ['device_id'],
          additionalProperties: false,
          properties: { device_id: uuidSchema },
        },
      },
    },
    async (request) => {
      const deviceId = parseUuid('device_id', request.body.device_id);
      const clientIp = request.ip || 'unknown';
      const now = ctx.now();
      const nonce = randomBytes(32);
      const expiresAt = new Date(now.getTime() + ctx.config.challengeTtlSeconds * 1000);
      await withTransaction(ctx.pool, async (db) => {
        await deleteExpiredChallenges(db, now);
        // Serialize issuers that share an address, then the device row, so the caps cannot race.
        await db.query('SELECT pg_advisory_xact_lock(hashtext($1)::bigint)', [`challenge:${clientIp}`]);
        if (!(await lockLiveDevice(db, deviceId))) throw notFound('device unknown or revoked');
        const outstanding = async (where: string, value: string) => {
          const { rows } = await db.query<{ n: number }>(
            `SELECT count(*)::int AS n FROM auth_challenges WHERE ${where} AND used_at IS NULL AND expires_at > $2`,
            [value, now],
          );
          return rows[0]!.n;
        };
        if ((await outstanding('device_id = $1', deviceId)) >= ctx.config.maxOutstandingChallengesPerDevice) {
          throw tooManyRequests('too many outstanding challenges for this device');
        }
        if ((await outstanding('client_ip = $1', clientIp)) >= ctx.config.maxOutstandingChallengesPerIp) {
          throw tooManyRequests('too many outstanding challenges from this client');
        }
        await db.query(
          'INSERT INTO auth_challenges (nonce, device_id, expires_at, client_ip) VALUES ($1, $2, $3, $4)',
          [nonce, deviceId, expiresAt, clientIp],
        );
      });
      return { nonce: toBase64(nonce), expires_at: expiresAt.toISOString() };
    },
  );

  app.post<{ Body: { device_id: string; nonce: string; signature: string } }>(
    '/v1/auth/token',
    {
      schema: {
        body: {
          type: 'object',
          required: ['device_id', 'nonce', 'signature'],
          additionalProperties: false,
          properties: { device_id: uuidSchema, nonce: base64Schema(32), signature: base64Schema(64) },
        },
      },
    },
    async (request) => {
      const deviceId = parseUuid('device_id', request.body.device_id);
      const nonce = decodeBase64Field('nonce', request.body.nonce, 32);
      const signature = decodeBase64Field('signature', request.body.signature, 64);
      await deleteExpiredChallenges(ctx.pool, ctx.now());

      // Consume the challenge first: a wrong signature still burns it.
      const used = await ctx.pool.query(
        `UPDATE auth_challenges SET used_at = $3
          WHERE nonce = $1 AND device_id = $2 AND used_at IS NULL AND expires_at > $3`,
        [nonce, deviceId, ctx.now()],
      );
      if (used.rowCount !== 1) throw unauthorized('invalid or expired challenge');

      const device = await loadDevice(ctx.pool, deviceId);
      const content = relayAuthContent(ctx.config.origin, nonce);
      if (!device || !verifyWithLabel(device.signatureKey, SignatureLabel.relayAuth, content, signature)) {
        throw unauthorized('signature does not verify');
      }

      const expiresAt = nowSeconds(ctx) + ctx.config.accessTokenTtlSeconds;
      return {
        access_token: issueAccessToken(ctx.config.tokenSecret, deviceId, expiresAt),
        token_type: 'Bearer',
        expires_at: new Date(expiresAt * 1000).toISOString(),
      };
    },
  );
}
