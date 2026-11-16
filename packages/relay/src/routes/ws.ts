import type { FastifyInstance } from 'fastify';
import { normalizeUuid } from '@agent-bridge/protocol';
import { requireDevice } from '../auth.ts';
import type { RelayContext } from '../context.ts';

// GET /v1/ws — server pushes RelayEvents (hub.ts) for every topic the device
// belongs to. The client may send:
//   { "type": "ack", "topic_id": "…", "seq": 42 }   after persisting messages up to seq
//   { "type": "ping" }                              answered with { "type": "pong" }
// Acks advance the device's fetch cursor, which retention uses to detect stale members.

const HEARTBEAT_MS = 30_000;

export function wsRoutes(app: FastifyInstance, ctx: RelayContext): void {
  app.get('/v1/ws', { websocket: true, onRequest: requireDevice(ctx) }, (socket, request) => {
    const deviceId = request.device.id;
    ctx.hub.add(deviceId, socket);

    let alive = true;
    socket.on('pong', () => {
      alive = true;
    });
    const heartbeat = setInterval(() => {
      if (!alive) return socket.terminate();
      alive = false;
      socket.ping();
    }, HEARTBEAT_MS);
    heartbeat.unref();

    socket.on('close', () => {
      clearInterval(heartbeat);
      ctx.hub.remove(deviceId, socket);
    });

    // Handle this socket's messages one at a time, in order: a pong sent after
    // an ack means the ack has been applied.
    let queue: Promise<void> = Promise.resolve();
    socket.on('message', (raw) => {
      queue = queue.then(async () => {
        let msg: { type?: unknown; topic_id?: unknown; seq?: unknown };
        try {
          msg = JSON.parse(raw.toString());
        } catch {
          return socket.send(JSON.stringify({ type: 'error', error: 'invalid_json' }));
        }
        if (msg.type === 'ping') return socket.send(JSON.stringify({ type: 'pong' }));
        if (msg.type === 'ack') {
          const topicId = typeof msg.topic_id === 'string' ? normalizeUuid(msg.topic_id) : null;
          if (topicId === null || !Number.isSafeInteger(msg.seq) || (msg.seq as number) < 0) {
            return socket.send(JSON.stringify({ type: 'error', error: 'invalid_ack' }));
          }
          // Bounded by the topic's last seq, and only for a current member.
          await ctx.pool.query(
            `UPDATE topic_members m SET last_fetched_seq = GREATEST(m.last_fetched_seq, LEAST($3::bigint, t.last_seq))
               FROM topics t
              WHERE t.id = m.topic_id AND m.topic_id = $1 AND m.device_id = $2 AND m.removed_at IS NULL`,
            [topicId, deviceId, msg.seq],
          );
          return;
        }
        socket.send(JSON.stringify({ type: 'error', error: 'unknown_type' }));
      }).catch((err: unknown) => request.log.error({ err }, 'websocket message handling failed'));
    });
  });
}
