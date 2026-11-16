import { createHmac, timingSafeEqual } from 'node:crypto';
import type { FastifyRequest } from 'fastify';
import { normalizeUuid, toBase64Url } from '@agent-bridge/protocol';
import { bytes } from './db.ts';
import type { Queryable } from './db.ts';
import { unauthorized } from './errors.ts';
import type { RelayContext } from './context.ts';

// Access tokens are stateless: v1.<payload>.<hmac>, payload = {d: device_id, e: expiry (unix s)}.
// Revocation is enforced by re-loading the device on every request.

export interface AuthedDevice {
  id: string;
  accountId: string;
  handle: string;
  signatureKey: Uint8Array;
  identityKey: Uint8Array;
}

declare module 'fastify' {
  interface FastifyRequest {
    device: AuthedDevice;
  }
}

function mac(secret: Uint8Array, data: string): Buffer {
  return createHmac('sha256', secret).update(data).digest();
}

export function issueAccessToken(secret: Uint8Array, deviceId: string, expiresAt: number): string {
  const payload = Buffer.from(JSON.stringify({ d: deviceId, e: expiresAt })).toString('base64url');
  return `v1.${payload}.${toBase64Url(mac(secret, `v1.${payload}`))}`;
}

/** Returns the device id, or null for a malformed, forged, or expired token. */
export function verifyAccessToken(secret: Uint8Array, token: string, nowSeconds: number): string | null {
  const parts = token.split('.');
  if (parts.length !== 3 || parts[0] !== 'v1') return null;
  const [, payload, signature] = parts as [string, string, string];
  const expected = mac(secret, `v1.${payload}`);
  const given = Buffer.from(signature, 'base64url');
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) return null;
  try {
    const { d, e } = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as { d: unknown; e: unknown };
    if (typeof d !== 'string' || typeof e !== 'number' || e <= nowSeconds) return null;
    return normalizeUuid(d);
  } catch {
    return null;
  }
}

export async function loadDevice(db: Queryable, deviceId: string): Promise<AuthedDevice | null> {
  const { rows } = await db.query<{
    id: string;
    account_id: string;
    handle: string;
    signature_pubkey: Buffer;
    identity_pubkey: Buffer;
  }>(
    `SELECT d.id, d.account_id, a.handle, d.signature_pubkey, a.identity_pubkey
       FROM devices d JOIN accounts a ON a.id = d.account_id
      WHERE d.id = $1 AND d.revoked_at IS NULL`,
    [deviceId],
  );
  const row = rows[0];
  if (!row) return null;
  return {
    id: row.id,
    accountId: row.account_id,
    handle: row.handle,
    signatureKey: bytes(row.signature_pubkey),
    identityKey: bytes(row.identity_pubkey),
  };
}

export function nowSeconds(ctx: RelayContext): number {
  return Math.floor(ctx.now().getTime() / 1000);
}

/** Fastify onRequest hook (runs before body parsing and validation): authenticates `Authorization: Bearer <token>` and sets request.device. */
export function requireDevice(ctx: RelayContext) {
  return async (request: FastifyRequest): Promise<void> => {
    const header = request.headers.authorization;
    const match = header?.match(/^Bearer ([A-Za-z0-9._-]+)$/);
    if (!match) throw unauthorized();
    const deviceId = verifyAccessToken(ctx.config.tokenSecret, match[1]!, nowSeconds(ctx));
    if (!deviceId) throw unauthorized('invalid or expired access token');
    const device = await loadDevice(ctx.pool, deviceId);
    if (!device) throw unauthorized('device unknown or revoked');
    request.device = device;
  };
}
