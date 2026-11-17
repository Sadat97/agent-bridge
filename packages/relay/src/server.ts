import { buildApp } from './app.ts';
import { loadConfig } from './config.ts';
import { createPool } from './db.ts';
import { migrate } from './migrate.ts';
import { runRetention } from './retention.ts';

const config = loadConfig();
const pool = createPool(config.databaseUrl);
await migrate(pool);

const { app, ctx } = await buildApp({ config, pool, logger: { level: process.env.LOG_LEVEL ?? 'info' } });

async function retentionTick(): Promise<void> {
  try {
    const result = await runRetention(ctx);
    app.log.info({ ...result, staleMembers: result.staleMembers.length }, 'retention run');
  } catch (err) {
    app.log.error({ err }, 'retention run failed');
  }
}
await retentionTick();
const timer = setInterval(retentionTick, config.retentionIntervalMs);
timer.unref();

let closing = false;
for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => {
    if (closing) return;
    closing = true;
    app.log.info({ signal }, 'shutting down');
    clearInterval(timer);
    void app.close().then(() => pool.end()).then(() => process.exit(0));
  });
}

await app.listen({ host: config.host, port: config.port });
