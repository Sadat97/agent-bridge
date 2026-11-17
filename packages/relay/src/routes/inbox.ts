import type { FastifyInstance } from 'fastify';
import { toBase64 } from '@agent-bridge/protocol';
import { requireDevice } from '../auth.ts';
import type { RelayContext } from '../context.ts';
import { bytes } from '../db.ts';
import { notFound } from '../errors.ts';
import { parseUuid } from '../validate.ts';

// Welcomes for a device that has been added to a topic but cannot read it yet.

export function inboxRoutes(app: FastifyInstance, ctx: RelayContext): void {
  const auth = { onRequest: requireDevice(ctx) };

  app.get('/v1/inbox', auth, async (request) => {
    const { rows } = await ctx.pool.query<{
      id: string;
      topic_id: string;
      commit_seq: number;
      welcome: Buffer;
      created_at: Date;
      expires_at: Date;
    }>(
      `SELECT id, topic_id, commit_seq, welcome, created_at, expires_at FROM welcomes
        WHERE recipient_device = $1 AND acked_at IS NULL AND expires_at > $2
        ORDER BY created_at`,
      [request.device.id, ctx.now()],
    );
    return {
      welcomes: rows.map((r) => ({
        id: r.id,
        topic_id: r.topic_id,
        commit_seq: r.commit_seq,
        welcome: toBase64(bytes(r.welcome)),
        created_at: r.created_at.toISOString(),
        expires_at: r.expires_at.toISOString(),
      })),
    };
  });

  app.post<{ Params: { id: string } }>('/v1/inbox/:id/ack', auth, async (request) => {
    const id = parseUuid('id', request.params.id);
    const { rows } = await ctx.pool.query<{ acked_at: Date }>(
      `UPDATE welcomes SET acked_at = COALESCE(acked_at, $3)
        WHERE id = $1 AND recipient_device = $2 RETURNING acked_at`,
      [id, request.device.id, ctx.now()],
    );
    if (!rows[0]) throw notFound();
    return { id, acked_at: rows[0].acked_at.toISOString() };
  });
}
