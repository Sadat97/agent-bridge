// The relay's core: per-topic sequencing (DESIGN.md section 5.1).
//
// Every POST locks the topic row, so for each topic there is exactly one
// writer at a time. A message is accepted only for the topic's current epoch,
// a commit advances the epoch, and membership changes are verified and applied
// in the same transaction that sequences the commit.

import type { FastifyInstance } from 'fastify';
import {
  addApprovalContent,
  bytesEqual,
  decodeMlsMessageHeader,
  decodeWelcomeMessage,
  removeApprovalContent,
  SignatureLabel,
  toBase64,
  uuidToBytes,
  verifyWithLabel,
} from '@agent-bridge/protocol';
import { nowSeconds, requireDevice } from '../auth.ts';
import type { RelayContext } from '../context.ts';
import { bytes, withTransaction } from '../db.ts';
import { badRequest, conflict, forbidden, gone, notFound, RelayError } from '../errors.ts';
import { approvalIdSchema, base64Schema, decodeBase64Field, parseUuid, uuidSchema } from '../validate.ts';
import { loadMembership } from './topics.ts';

interface PostBody {
  message: string;
  membership?: {
    adds?: Array<{ device_id: string; approval_id: string; expires_at: number; approval: string }>;
    removes?: Array<{ device_id: string; approval_id: string; approval?: string; leave_seq?: number }>;
  };
  welcome?: { message: string; recipients: string[] };
}

interface AddChange {
  deviceId: string;
  approvalId: string;
  expiresAt: number;
  approval: Uint8Array;
}

interface RemoveChange {
  deviceId: string;
  approvalId: string;
  approval: Uint8Array | null;
  leaveSeq: number | null;
}

function postBodySchema(maxMessageBytes: number) {
  return {
    type: 'object',
    required: ['message'],
    additionalProperties: false,
    properties: {
      message: base64Schema(maxMessageBytes),
      membership: {
        type: 'object',
        additionalProperties: false,
        properties: {
          adds: {
            type: 'array',
            maxItems: 50,
            items: {
              type: 'object',
              required: ['device_id', 'approval_id', 'expires_at', 'approval'],
              additionalProperties: false,
              properties: {
                device_id: uuidSchema,
                approval_id: approvalIdSchema,
                expires_at: { type: 'integer', minimum: 0 },
                approval: base64Schema(64),
              },
            },
          },
          removes: {
            type: 'array',
            maxItems: 50,
            items: {
              type: 'object',
              required: ['device_id', 'approval_id'],
              additionalProperties: false,
              properties: {
                device_id: uuidSchema,
                approval_id: approvalIdSchema,
                approval: base64Schema(64),
                leave_seq: { type: 'integer', minimum: 1 },
              },
            },
          },
        },
      },
      welcome: {
        type: 'object',
        required: ['message', 'recipients'],
        additionalProperties: false,
        properties: {
          message: base64Schema(maxMessageBytes),
          recipients: { type: 'array', minItems: 1, maxItems: 50, items: uuidSchema },
        },
      },
    },
  } as const;
}

function assertUnique(values: string[], code: string, what: string): void {
  if (new Set(values).size !== values.length) throw badRequest(code, `duplicate ${what}`);
}

export function messageRoutes(app: FastifyInstance, ctx: RelayContext): void {
  const auth = { onRequest: requireDevice(ctx) };

  app.post<{ Params: { id: string }; Body: PostBody }>(
    '/v1/topics/:id/messages',
    { ...auth, schema: { body: postBodySchema(ctx.config.maxMessageBytes) } },
    async (request, reply) => {
      const device = request.device;
      const topicId = parseUuid('id', request.params.id);
      const body = request.body;

      // 1. Read the unencrypted MLS header. Client-declared values are never trusted.
      const message = decodeBase64Field('message', body.message);
      if (message.length > ctx.config.maxMessageBytes) {
        throw new RelayError(413, 'message_too_large', `MLS messages are limited to ${ctx.config.maxMessageBytes} bytes`);
      }
      let header;
      try {
        header = decodeMlsMessageHeader(message);
      } catch {
        throw badRequest('invalid_mls_message', 'message is not a well-formed MLSMessage');
      }
      if (header.wireFormat !== 'private_message') {
        throw badRequest('unsupported_wire_format', 'only MLS PrivateMessages are accepted');
      }
      if (!bytesEqual(header.groupId, uuidToBytes(topicId))) {
        throw badRequest('group_mismatch', 'MLS group_id does not match the topic id');
      }
      if (header.contentType === 'proposal') {
        throw badRequest('proposals_not_supported', 'send proposals inline in a commit');
      }
      if (header.epoch > BigInt(Number.MAX_SAFE_INTEGER)) throw badRequest('invalid_epoch', 'epoch out of range');
      const epoch = Number(header.epoch);
      const isCommit = header.contentType === 'commit';

      // 2. Shape-check the membership delta and Welcome before taking the lock.
      if (!isCommit && (body.membership !== undefined || body.welcome !== undefined)) {
        throw badRequest('membership_requires_commit', 'membership changes and Welcomes travel only with a commit');
      }
      const adds: AddChange[] = (body.membership?.adds ?? []).map((a, i) => ({
        deviceId: parseUuid(`membership.adds[${i}].device_id`, a.device_id),
        approvalId: a.approval_id,
        expiresAt: a.expires_at,
        approval: decodeBase64Field(`membership.adds[${i}].approval`, a.approval, 64),
      }));
      const removes: RemoveChange[] = (body.membership?.removes ?? []).map((r, i) => {
        const approval = r.approval === undefined ? null : decodeBase64Field(`membership.removes[${i}].approval`, r.approval, 64);
        const leaveSeq = r.leave_seq ?? null;
        if ((approval === null) === (leaveSeq === null)) {
          throw badRequest('invalid_remove', `membership.removes[${i}] needs exactly one of approval or leave_seq`);
        }
        return { deviceId: parseUuid(`membership.removes[${i}].device_id`, r.device_id), approvalId: r.approval_id, approval, leaveSeq };
      });
      assertUnique([...adds, ...removes].map((c) => c.approvalId), 'duplicate_approval', 'approval_id');
      assertUnique(adds.map((a) => a.deviceId), 'duplicate_device', 'device in adds');
      assertUnique(removes.map((r) => r.deviceId), 'duplicate_device', 'device in removes');

      let welcome: { message: Uint8Array; recipients: string[] } | null = null;
      if (body.welcome) {
        const welcomeMessage = decodeBase64Field('welcome.message', body.welcome.message);
        try {
          decodeWelcomeMessage(welcomeMessage);
        } catch {
          throw badRequest('invalid_welcome', 'welcome.message is not an MLS Welcome');
        }
        welcome = {
          message: welcomeMessage,
          recipients: body.welcome.recipients.map((r, i) => parseUuid(`welcome.recipients[${i}]`, r)),
        };
      }
      const addIds = new Set(adds.map((a) => a.deviceId));
      const welcomeMatches =
        welcome === null
          ? addIds.size === 0
          : welcome.recipients.length === addIds.size && welcome.recipients.every((r) => addIds.has(r));
      if (!welcomeMatches) {
        throw badRequest('welcome_mismatch', 'a commit with adds needs a Welcome addressed to exactly the added devices');
      }

      // 3. Sequence, under the topic lock.
      const result = await withTransaction(ctx.pool, async (db) => {
        const m = await loadMembership(db, topicId, device.id, { lockTopic: true });
        if (!m) throw notFound();
        if (m.closed_at) throw conflict('topic_closed', 'the topic is closed');
        if (m.stale_at) throw forbidden('member_stale', 'this device fell behind retention and must be re-added');
        if (epoch !== m.current_epoch) {
          throw conflict('stale_epoch', `the topic is at epoch ${m.current_epoch}`, { current_epoch: m.current_epoch });
        }

        const seq = m.last_seq + 1;
        const newEpoch = isCommit ? m.current_epoch + 1 : m.current_epoch;
        const changesMembership = adds.length + removes.length > 0;
        if (changesMembership && m.owner_account !== device.accountId) {
          throw forbidden('not_topic_owner', 'only the topic owner commits membership changes');
        }

        if (changesMembership) {
          const ids = [...adds, ...removes].map((c) => c.approvalId);
          const used = await db.query<{ approval_id: string }>(
            'SELECT approval_id FROM membership_changes WHERE topic_id = $1 AND approval_id = ANY($2::text[])',
            [topicId, ids],
          );
          if (used.rows.length) {
            throw conflict('approval_used', 'approval already used', { approval_ids: used.rows.map((r) => r.approval_id) });
          }
        }

        for (const r of removes) {
          const { rows } = await db.query<{ role: string; signature_pubkey: Buffer }>(
            `SELECT m.role, d.signature_pubkey FROM topic_members m JOIN devices d ON d.id = m.device_id
              WHERE m.topic_id = $1 AND m.device_id = $2 AND m.removed_at IS NULL`,
            [topicId, r.deviceId],
          );
          const member = rows[0];
          if (!member) throw badRequest('not_a_member', `${r.deviceId} is not a current member`);
          if (member.role === 'owner') throw badRequest('cannot_remove_owner', 'the topic owner cannot be removed');
          if (r.approval) {
            const content = removeApprovalContent({
              topicId,
              approvalId: r.approvalId,
              removedDeviceKey: bytes(member.signature_pubkey),
            });
            if (!verifyWithLabel(device.identityKey, SignatureLabel.remove, content, r.approval)) {
              throw forbidden('invalid_approval', `remove approval for ${r.deviceId} does not verify`);
            }
          } else {
            const leave = await db.query(
              `SELECT 1 FROM mls_messages
                WHERE topic_id = $1 AND seq = $2 AND content = 'application' AND sender_device = $3`,
              [topicId, r.leaveSeq, r.deviceId],
            );
            if (!leave.rowCount) throw badRequest('invalid_leave', `leave_seq is not a message from ${r.deviceId}`);
          }
        }

        const removedIds = new Set(removes.map((r) => r.deviceId));
        const addTargets: Array<{ deviceId: string; accountId: string }> = [];
        for (const a of adds) {
          const { rows } = await db.query<{ account_id: string; signature_pubkey: Buffer; identity_pubkey: Buffer }>(
            `SELECT d.account_id, d.signature_pubkey, a.identity_pubkey FROM devices d JOIN accounts a ON a.id = d.account_id
              WHERE d.id = $1 AND d.revoked_at IS NULL`,
            [a.deviceId],
          );
          const target = rows[0];
          if (!target) throw badRequest('unknown_device', `${a.deviceId} is unknown or revoked`);
          const existing = await db.query(
            'SELECT 1 FROM topic_members WHERE topic_id = $1 AND device_id = $2 AND removed_at IS NULL',
            [topicId, a.deviceId],
          );
          if (existing.rowCount && !removedIds.has(a.deviceId)) {
            throw conflict('already_member', `${a.deviceId} is already a member`);
          }
          if (a.expiresAt <= nowSeconds(ctx)) throw badRequest('approval_expired', `add approval for ${a.deviceId} expired`);
          const content = addApprovalContent({
            topicId,
            approvalId: a.approvalId,
            inviteeIdentityKey: bytes(target.identity_pubkey),
            inviteeDeviceKey: bytes(target.signature_pubkey),
            role: 'member',
            expiresAt: a.expiresAt,
          });
          if (!verifyWithLabel(device.identityKey, SignatureLabel.add, content, a.approval)) {
            throw forbidden('invalid_approval', `add approval for ${a.deviceId} does not verify`);
          }
          addTargets.push({ deviceId: a.deviceId, accountId: target.account_id });
        }

        const now = ctx.now();
        await db.query(
          'INSERT INTO mls_messages (topic_id, seq, epoch, content, sender_device, message) VALUES ($1, $2, $3, $4, $5, $6)',
          [topicId, seq, epoch, isCommit ? 'commit' : 'application', device.id, message],
        );
        await db.query('UPDATE topics SET last_seq = $2, current_epoch = $3 WHERE id = $1', [topicId, seq, newEpoch]);
        // A sender that was caught up now also has its own message.
        await db.query(
          'UPDATE topic_members SET last_fetched_seq = $3 WHERE topic_id = $1 AND device_id = $2 AND last_fetched_seq = $3 - 1',
          [topicId, device.id, seq],
        );

        for (const r of removes) {
          await db.query('UPDATE topic_members SET removed_at = $3 WHERE topic_id = $1 AND device_id = $2', [
            topicId,
            r.deviceId,
            now,
          ]);
          await db.query(
            `INSERT INTO membership_changes (topic_id, approval_id, commit_seq, device_id, change, approval, leave_seq)
             VALUES ($1, $2, $3, $4, $5, $6, $7)`,
            [topicId, r.approvalId, seq, r.deviceId, r.approval ? 'remove' : 'leave', r.approval, r.leaveSeq],
          );
        }
        for (const [i, t] of addTargets.entries()) {
          await db.query(
            `INSERT INTO topic_members (topic_id, device_id, account_id, role, joined_epoch, joined_seq, last_fetched_seq)
             VALUES ($1, $2, $3, 'member', $4, $5, $5)
             ON CONFLICT (topic_id, device_id) DO UPDATE
               SET account_id = EXCLUDED.account_id, role = 'member', joined_epoch = EXCLUDED.joined_epoch,
                   joined_seq = EXCLUDED.joined_seq, last_fetched_seq = EXCLUDED.joined_seq,
                   stale_at = NULL, removed_at = NULL`,
            [topicId, t.deviceId, t.accountId, newEpoch, seq],
          );
          await db.query(
            `INSERT INTO membership_changes (topic_id, approval_id, commit_seq, device_id, change, approval)
             VALUES ($1, $2, $3, $4, 'add', $5)`,
            [topicId, adds[i]!.approvalId, seq, t.deviceId, adds[i]!.approval],
          );
        }

        const welcomeIds: Array<{ id: string; recipient: string }> = [];
        if (welcome) {
          const expiresAt = new Date(now.getTime() + ctx.config.welcomeTtlDays * 86_400_000);
          for (const recipient of welcome.recipients) {
            const { rows } = await db.query<{ id: string }>(
              `INSERT INTO welcomes (topic_id, recipient_device, commit_seq, welcome, expires_at)
               VALUES ($1, $2, $3, $4, $5) RETURNING id`,
              [topicId, recipient, seq, welcome.message, expiresAt],
            );
            welcomeIds.push({ id: rows[0]!.id, recipient });
          }
        }
        if (changesMembership) {
          await db.query(
            "INSERT INTO audit_log (account_id, device_id, topic_id, action) VALUES ($1, $2, $3, 'membership_commit')",
            [device.accountId, device.id, topicId],
          );
        }

        // Notify current members and anyone this commit removed; new members start from their Welcome.
        const { rows: members } = await db.query<{ device_id: string }>(
          'SELECT device_id FROM topic_members WHERE topic_id = $1 AND removed_at IS NULL',
          [topicId],
        );
        const notify = members.map((r) => r.device_id).filter((id) => !addIds.has(id));
        return { seq, newEpoch, notify: [...notify, ...removedIds], welcomeIds };
      });

      ctx.hub.publish(result.notify, {
        type: 'message',
        topic_id: topicId,
        seq: result.seq,
        epoch,
        content: isCommit ? 'commit' : 'application',
        sender_device: device.id,
        ...(message.length <= ctx.config.wsInlineMaxBytes ? { message: toBase64(message) } : {}),
      });
      for (const w of result.welcomeIds) {
        ctx.hub.publish([w.recipient], { type: 'welcome', id: w.id, topic_id: topicId, commit_seq: result.seq });
      }
      return reply.code(201).send({ seq: result.seq, epoch: result.newEpoch });
    },
  );

  app.get<{ Params: { id: string }; Querystring: { after_seq?: number; limit?: number } }>(
    '/v1/topics/:id/messages',
    {
      ...auth,
      schema: {
        querystring: {
          type: 'object',
          additionalProperties: false,
          properties: {
            after_seq: { type: 'integer', minimum: 0 },
            limit: { type: 'integer', minimum: 1, maximum: 500, default: 100 },
          },
        },
      },
    },
    async (request) => {
      const device = request.device;
      const topicId = parseUuid('id', request.params.id);
      const m = await loadMembership(ctx.pool, topicId, device.id);
      if (!m) throw notFound();
      if (m.stale_at) throw forbidden('member_stale', 'this device fell behind retention and must be re-added');

      // A member never receives ciphertext from before it joined.
      const after = Math.max(request.query.after_seq ?? m.joined_seq, m.joined_seq);
      if (after < m.pruned_through_seq) {
        throw gone('pruned', 'messages after this cursor were deleted by retention', { min_seq: m.pruned_through_seq + 1 });
      }

      const { rows } = await ctx.pool.query<{
        seq: number;
        epoch: number;
        content: 'commit' | 'application';
        sender_device: string;
        message: Buffer;
        created_at: Date;
      }>(
        `SELECT seq, epoch, content, sender_device, message, created_at FROM mls_messages
          WHERE topic_id = $1 AND seq > $2 ORDER BY seq LIMIT $3`,
        [topicId, after, request.query.limit ?? 100],
      );
      const last = rows.at(-1);
      if (last) {
        await ctx.pool.query(
          `UPDATE topic_members SET last_fetched_seq = GREATEST(last_fetched_seq, $3)
            WHERE topic_id = $1 AND device_id = $2`,
          [topicId, device.id, last.seq],
        );
      }
      return {
        messages: rows.map((r) => ({
          seq: r.seq,
          epoch: r.epoch,
          content: r.content,
          sender_device: r.sender_device,
          message: toBase64(bytes(r.message)),
          created_at: r.created_at.toISOString(),
        })),
        last_seq: Math.max(m.last_seq, last?.seq ?? 0),
      };
    },
  );
}
