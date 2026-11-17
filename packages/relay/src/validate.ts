import { fromBase64, normalizeUuid } from '@agent-bridge/protocol';
import { badRequest } from './errors.ts';

// Shared JSON-schema fragments and decoders. Fastify validates shape; these
// turn strings into bytes and UUIDs with precise errors.

export const uuidSchema = { type: 'string', minLength: 36, maxLength: 36 } as const;
export const base64Schema = (maxBytes: number) =>
  ({ type: 'string', minLength: 1, maxLength: Math.ceil(maxBytes / 3) * 4 }) as const;
export const approvalIdSchema = { type: 'string', pattern: '^[A-Za-z0-9_-]{1,64}$' } as const;

export function decodeBase64Field(field: string, value: string, exactLength?: number): Uint8Array {
  const decoded = fromBase64(value);
  if (decoded === null) throw badRequest('invalid_base64', `${field} is not valid base64`);
  if (exactLength !== undefined && decoded.length !== exactLength) {
    throw badRequest('invalid_length', `${field} must be ${exactLength} bytes`);
  }
  return decoded;
}

export function parseUuid(field: string, value: string): string {
  const id = normalizeUuid(value);
  if (id === null) throw badRequest('invalid_uuid', `${field} must be a UUID`);
  return id;
}

/** Postgres unique-violation constraint name, if `err` is one. */
export function uniqueViolation(err: unknown): string | null {
  const e = err as { code?: string; constraint?: string };
  return e?.code === '23505' ? (e.constraint ?? '') : null;
}
