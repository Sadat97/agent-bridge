import type { FastifyInstance } from 'fastify';
import { normalizeUuid } from '@agent-bridge/protocol';
import { loadDevice, nowSeconds, requireDevice } from '../auth.ts';
import type { RelayContext } from '../context.ts';
import { withTransaction } from '../db.ts';
import { WS_CLOSE_EXPIRED, WS_CLOSE_REVOKED } from '../deliver.ts';
import { noteCursor } from './topics.ts';

// GET /v1/ws — server pushes RelayEvents (hub.ts) for every topic the device
// belongs to. The client may send:
//   { "type": "ack", "topic_id": "…", "seq": 42 }   after persisting messages up to seq
//   { "type": "ping" }                              answered with { "type": "pong" }
// Acks advance the device's fetch cursor, which retention uses to detect stale members.
//
// The socket is closed when its access token expires or the device is revoked.
// Until then it is re-checked on every client frame and on every fan-out.

const HEARTBEAT_MS = 30_000;

export function wsRoutes(app: FastifyInstance, ctx: RelayContext): void {
  app.get('/v1/ws', { websocket: true, onRequest: requireDevice(ctx) }, (socket, request) => {
    const deviceId = request.device.id;
    const expiresAtMs = request.tokenExpiresAt * 1000;
    if (ctx.hub.socketCount(deviceId) >= ctx.config.maxSocketsPerDevice) {
      socket.close(4029, 'too_many_sockets');
      return;
    }
    ctx.hub.add(deviceId, socket, expiresAtMs);

    let alive = true;
    let open = true;
    socket.on('pong', () => {
      alive = true;
    });
    const heartbeat = setInterval(() => {
      if (!open) return;
      if (ctx.now().getTime() >= expiresAtMs) {
        end(WS_CLOSE_EXPIRED, 'token_expired');
        return;
      }
      if (!alive) return socket.terminate();
      alive = false;
      socket.ping();
    }, HEARTBEAT_MS);
    heartbeat.unref();

    const end = (code: number, reason: string): void => {
      if (!open) return;
      open = false;
      clearInterval(heartbeat);
      ctx.hub.closeSocket(deviceId, socket, code, reason);
    };

    socket.on('close', () => {
      open = false;
      clearInterval(heartbeat);
      ctx.hub.remove(deviceId, socket);
    });

    /** False once the token has expired or the device has been revoked. Closes the socket. */
    const stillAuthorized = async (): Promise<boolean> => {
      if (!open || nowSeconds(ctx) >= request.tokenExpiresAt) {
        end(WS_CLOSE_EXPIRED, 'token_expired');
        return false;
      }
      const device = await loadDevice(ctx.pool, deviceId);
      if (!device) {
        // Every socket for this device is done, including this one.
        open = false;
        clearInterval(heartbeat);
        ctx.hub.closeDevice(deviceId, WS_CLOSE_REVOKED, 'device_revoked');
        return false;
      }
      return true;
    };

    // Handle this socket's messages one at a time, in order: a pong sent after
    // an ack means the ack has been applied.
    let queue: Promise<void> = Promise.resolve();
    socket.on('message', (raw) => {
      queue = queue.then(async () => {
        if (!(await stillAuthorized())) return;
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
          // Re-check after the parse so a revocation between frames is not applied.
          if (!(await stillAuthorized())) return;
          // Bounded by the topic's last seq. Same topic lock as retention, so the
          // cursor and stale_at cannot diverge.
          await withTransaction(ctx.pool, (db) => noteCursor(db, topicId, deviceId, msg.seq as number));
          return;
        }
        socket.send(JSON.stringify({ type: 'error', error: 'unknown_type' }));
      }).catch((err: unknown) => request.log.error({ err }, 'websocket message handling failed'));
    });
  });
}
