import Fastify from 'fastify';
import type { FastifyInstance, FastifyServerOptions } from 'fastify';
import websocket from '@fastify/websocket';
import type { RelayConfig } from './config.ts';
import type { RelayContext } from './context.ts';
import type { Pool } from './db.ts';
import { RelayError } from './errors.ts';
import { Hub } from './hub.ts';
import { identityRoutes } from './routes/identity.ts';
import { inboxRoutes } from './routes/inbox.ts';
import { keyPackageRoutes } from './routes/key-packages.ts';
import { messageRoutes } from './routes/messages.ts';
import { topicRoutes } from './routes/topics.ts';
import { wsRoutes } from './routes/ws.ts';

export type { RelayConfig } from './config.ts';
export type { RelayContext } from './context.ts';
export { loadConfig, defaults } from './config.ts';
export { createPool } from './db.ts';
export { migrate } from './migrate.ts';
export { runRetention } from './retention.ts';
export { Hub } from './hub.ts';

export interface BuildOptions {
  config: RelayConfig;
  pool: Pool;
  now?: () => Date;
  logger?: FastifyServerOptions['logger'];
}

export async function buildApp(opts: BuildOptions): Promise<{ app: FastifyInstance; ctx: RelayContext }> {
  const ctx: RelayContext = { config: opts.config, pool: opts.pool, hub: new Hub(), now: opts.now ?? (() => new Date()) };

  const app = Fastify({
    logger: opts.logger ?? false,
    // A commit and its Welcome, base64-encoded, plus JSON overhead.
    bodyLimit: Math.ceil((opts.config.maxMessageBytes * 2 * 4) / 3) + 64 * 1024,
    trustProxy: opts.config.trustProxy,
  });

  // Client-to-server WebSocket frames are only acks and pings.
  await app.register(websocket, { options: { maxPayload: 4 * 1024 } });

  app.setErrorHandler((err: Error & { statusCode?: number; validation?: unknown; code?: string }, request, reply) => {
    if (err instanceof RelayError) {
      return reply
        .code(err.statusCode)
        .send({ error: err.code, message: err.message, ...(err.details ? { details: err.details } : {}) });
    }
    if (err.validation) return reply.code(400).send({ error: 'invalid_request', message: err.message });
    if (err.statusCode === 413) return reply.code(413).send({ error: 'payload_too_large', message: err.message });
    if (err.statusCode && err.statusCode >= 400 && err.statusCode < 500) {
      return reply.code(err.statusCode).send({ error: 'bad_request', message: err.message });
    }
    request.log.error({ err }, 'unhandled error');
    return reply.code(500).send({ error: 'internal', message: 'internal error' });
  });
  app.setNotFoundHandler((_request, reply) => reply.code(404).send({ error: 'not_found', message: 'no such route' }));

  app.get('/healthz', async () => {
    await ctx.pool.query('SELECT 1');
    return { ok: true, connected_devices: ctx.hub.connectedDevices };
  });

  identityRoutes(app, ctx);
  keyPackageRoutes(app, ctx);
  topicRoutes(app, ctx);
  messageRoutes(app, ctx);
  inboxRoutes(app, ctx);
  wsRoutes(app, ctx);

  return { app, ctx };
}
