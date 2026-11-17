import type { FastifyInstance } from 'fastify';
import { requireDevice } from '../auth.ts';
import type { RelayContext } from '../context.ts';
import { withTransaction } from '../db.ts';
import type { Queryable } from '../db.ts';
import { conflict, forbidden, notFound } from '../errors.ts';
import { parseUuid, uniqueViolation, uuidSchema } from '../validate.ts';

export interface Membership {
  topic_id: string;
  owner_account: string;
  current_epoch: number;
  last_seq: number;
  pruned_through_seq: number;
  closed_at: Date | null;
  role: 'owner' | 'member';
  joined_seq: number;
  last_fetched_seq: number;
  stale_at: Date | null;
}

/** The caller's current (not removed) membership in a topic, joined with the topic row. */
export async function loadMembership(
  db: Queryable,
  topicId: string,
  deviceId: string,
  opts: { lockTopic?: boolean } = {},
): Promise<Membership | null> {
  // Lock the topic row first so every writer to a topic is serialized (DESIGN.md 5.1).
  if (opts.lockTopic) await db.query('SELECT 1 FROM topics WHERE id = $1 FOR UPDATE', [topicId]);
  const { rows } = await db.query<Membership>(
    `SELECT t.id AS topic_id, t.owner_account, t.current_epoch, t.last_seq, t.pruned_through_seq, t.closed_at,
            m.role, m.joined_seq, m.last_fetched_seq, m.stale_at
       FROM topic_members m JOIN topics t ON t.id = m.topic_id
      WHERE m.topic_id = $1 AND m.device_id = $2 AND m.removed_at IS NULL`,
    [topicId, deviceId],
  );
  return rows[0] ?? null;
}

/**
 * Move a member's fetch cursor under the topic lock, and clear `stale_at` once
 * the cursor is no longer behind the retained prefix. `caughtUpOnly` is the
 * sender case: the cursor advances only from `seq - 1`, so a member who was
 * already behind does not skip the gap.
 */
export async function noteCursor(
  db: Queryable,
  topicId: string,
  deviceId: string,
  seq: number,
  opts: { caughtUpOnly?: boolean } = {},
): Promise<void> {
  await db.query('SELECT 1 FROM topics WHERE id = $1 FOR UPDATE', [topicId]);
  if (opts.caughtUpOnly) {
    await db.query(
      `UPDATE topic_members m
          SET last_fetched_seq = $3,
              stale_at = CASE WHEN $3 >= t.pruned_through_seq THEN NULL ELSE m.stale_at END
         FROM topics t
        WHERE t.id = m.topic_id AND m.topic_id = $1 AND m.device_id = $2
          AND m.removed_at IS NULL AND m.last_fetched_seq = $3 - 1`,
      [topicId, deviceId, seq],
    );
    return;
  }
  await db.query(
    `UPDATE topic_members m
        SET last_fetched_seq = GREATEST(m.last_fetched_seq, LEAST($3::bigint, t.last_seq)),
            stale_at = CASE
              WHEN GREATEST(m.last_fetched_seq, LEAST($3::bigint, t.last_seq)) >= t.pruned_through_seq THEN NULL
              ELSE m.stale_at
            END
       FROM topics t
      WHERE t.id = m.topic_id AND m.topic_id = $1 AND m.device_id = $2 AND m.removed_at IS NULL`,
    [topicId, deviceId, seq],
  );
}

async function topicViews(db: Queryable, deviceId: string, topicId?: string) {
  const { rows: topics } = await db.query<{
    id: string;
    owner: string;
    role: string;
    current_epoch: number;
    last_seq: number;
    pruned_through_seq: number;
    closed_at: Date | null;
    stale_at: Date | null;
  }>(
    `SELECT t.id, oa.handle AS owner, m.role, t.current_epoch, t.last_seq, t.pruned_through_seq, t.closed_at, m.stale_at
       FROM topic_members m
       JOIN topics t ON t.id = m.topic_id
       JOIN accounts oa ON oa.id = t.owner_account
      WHERE m.device_id = $1 AND m.removed_at IS NULL AND ($2::uuid IS NULL OR t.id = $2)
      ORDER BY t.created_at`,
    [deviceId, topicId ?? null],
  );
  if (topics.length === 0) return [];

  const { rows: members } = await db.query<{
    topic_id: string;
    device_id: string;
    handle: string;
    role: string;
    joined_epoch: number;
    stale: boolean;
  }>(
    `SELECT m.topic_id, m.device_id, a.handle, m.role, m.joined_epoch, m.stale_at IS NOT NULL AS stale
       FROM topic_members m JOIN accounts a ON a.id = m.account_id
      WHERE m.topic_id = ANY($1::uuid[]) AND m.removed_at IS NULL
      ORDER BY m.joined_seq, a.handle`,
    [topics.map((t) => t.id)],
  );

  return topics.map((t) => ({
    topic_id: t.id,
    owner: t.owner,
    role: t.role,
    epoch: t.current_epoch,
    last_seq: t.last_seq,
    min_seq: t.pruned_through_seq + 1,
    closed_at: t.closed_at?.toISOString() ?? null,
    stale: t.stale_at !== null,
    members: members
      .filter((m) => m.topic_id === t.id)
      .map(({ device_id, handle, role, joined_epoch, stale }) => ({ device_id, handle, role, joined_epoch, stale })),
  }));
}

export function topicRoutes(app: FastifyInstance, ctx: RelayContext): void {
  const auth = { onRequest: requireDevice(ctx) };

  // Create a topic. The id is the MLS group_id; the caller becomes topic owner at epoch 0.
  app.post<{ Body: { id: string } }>(
    '/v1/topics',
    {
      ...auth,
      schema: {
        body: { type: 'object', required: ['id'], additionalProperties: false, properties: { id: uuidSchema } },
      },
    },
    async (request, reply) => {
      const topicId = parseUuid('id', request.body.id);
      const device = request.device;
      try {
        await withTransaction(ctx.pool, async (db) => {
          await db.query('INSERT INTO topics (id, owner_account) VALUES ($1, $2)', [topicId, device.accountId]);
          await db.query(
            `INSERT INTO topic_members (topic_id, device_id, account_id, role, joined_epoch, joined_seq, last_fetched_seq)
             VALUES ($1, $2, $3, 'owner', 0, 0, 0)`,
            [topicId, device.id, device.accountId],
          );
          await db.query("INSERT INTO audit_log (account_id, device_id, topic_id, action) VALUES ($1, $2, $3, 'create_topic')", [
            device.accountId,
            device.id,
            topicId,
          ]);
        });
      } catch (err) {
        if (uniqueViolation(err) !== null) throw conflict('topic_exists', 'a topic with this id already exists');
        throw err;
      }
      return reply.code(201).send({ topic_id: topicId, epoch: 0, last_seq: 0 });
    },
  );

  app.get('/v1/topics', auth, async (request) => ({ topics: await topicViews(ctx.pool, request.device.id) }));

  app.get<{ Params: { id: string } }>('/v1/topics/:id', auth, async (request) => {
    const [view] = await topicViews(ctx.pool, request.device.id, parseUuid('id', request.params.id));
    if (!view) throw notFound();
    return view;
  });

  app.post<{ Params: { id: string } }>('/v1/topics/:id/close', auth, async (request) => {
    const topicId = parseUuid('id', request.params.id);
    const device = request.device;
    const membership = await loadMembership(ctx.pool, topicId, device.id);
    if (!membership) throw notFound();
    if (membership.owner_account !== device.accountId) {
      throw forbidden('not_topic_owner', 'only the topic owner can close a topic');
    }
    const { rows } = await ctx.pool.query<{ closed_at: Date }>(
      'UPDATE topics SET closed_at = COALESCE(closed_at, $2) WHERE id = $1 RETURNING closed_at',
      [topicId, ctx.now()],
    );
    await ctx.pool.query("INSERT INTO audit_log (account_id, device_id, topic_id, action) VALUES ($1, $2, $3, 'close')", [
      device.accountId,
      device.id,
      topicId,
    ]);
    return { topic_id: topicId, closed_at: rows[0]!.closed_at.toISOString() };
  });
}
