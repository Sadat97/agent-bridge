export interface RelayConfig {
  databaseUrl: string;
  /** Public origin, e.g. https://relay.example.com. Bound into every login signature. */
  origin: string;
  /** HMAC key for access tokens. */
  tokenSecret: Uint8Array;
  host: string;
  port: number;

  retentionDays: number;
  welcomeTtlDays: number;
  keyPackageTtlDays: number;
  accessTokenTtlSeconds: number;
  challengeTtlSeconds: number;
  /** Notify a device when its unclaimed KeyPackages drop below this. */
  keyPackageLowWatermark: number;
  /** Per claiming device, per rolling hour. Design 8.4; the number is the relay default. */
  keyPackageClaimsPerHour: number;
  /** Per sending device, per rolling minute. Design 8.4; the number is the relay default. */
  postsPerMinute: number;
  /** Largest MLS message accepted, in bytes. */
  maxMessageBytes: number;
  /** Messages up to this size are pushed inline over WebSocket. */
  wsInlineMaxBytes: number;
  retentionIntervalMs: number;
}

export const defaults = {
  retentionDays: 30,
  welcomeTtlDays: 7,
  keyPackageTtlDays: 30,
  accessTokenTtlSeconds: 15 * 60,
  challengeTtlSeconds: 60,
  keyPackageLowWatermark: 10,
  keyPackageClaimsPerHour: 30,
  postsPerMinute: 60,
  maxMessageBytes: 1024 * 1024,
  wsInlineMaxBytes: 64 * 1024,
  retentionIntervalMs: 60 * 60 * 1000,
} satisfies Partial<RelayConfig>;

function required(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name];
  if (value === undefined || value === '') throw new Error(`${name} is required`);
  return value;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): RelayConfig {
  const secret = required(env, 'RELAY_TOKEN_SECRET');
  if (secret.length < 32) throw new Error('RELAY_TOKEN_SECRET must be at least 32 characters');

  const origin = new URL(required(env, 'RELAY_ORIGIN')).origin;
  const port = Number(env.PORT ?? '8080');
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error('PORT must be a valid port');

  return {
    ...defaults,
    databaseUrl: required(env, 'DATABASE_URL'),
    origin,
    tokenSecret: new TextEncoder().encode(secret),
    host: env.HOST ?? '127.0.0.1',
    port,
  };
}
