import { timingSafeEqual } from 'node:crypto';

const BASE64_RE = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder('utf-8', { fatal: true });

/** Strict standard base64 (with padding). Returns null for anything else. */
export function fromBase64(value: string): Uint8Array | null {
  if (!BASE64_RE.test(value)) return null;
  return new Uint8Array(Buffer.from(value, 'base64'));
}

export function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('base64');
}

export function toBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('base64url');
}

export function utf8(value: string): Uint8Array {
  return textEncoder.encode(value);
}

export function fromUtf8(bytes: Uint8Array): string {
  return textDecoder.decode(bytes);
}

/** Constant-time when lengths match. */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && timingSafeEqual(a, b);
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, p) => sum + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

/** Canonical form is lowercase; any case is accepted and normalized. */
export function normalizeUuid(value: string): string | null {
  const lower = value.toLowerCase();
  return UUID_RE.test(lower) ? lower : null;
}

/** A topic id doubles as the MLS group_id: the 16 raw bytes of the UUID. */
export function uuidToBytes(value: string): Uint8Array {
  const id = normalizeUuid(value);
  if (id === null) throw new TypeError(`not a UUID: ${value}`);
  return new Uint8Array(Buffer.from(id.replaceAll('-', ''), 'hex'));
}

export function bytesToUuid(bytes: Uint8Array): string {
  if (bytes.length !== 16) throw new TypeError('UUID must be 16 bytes');
  const hex = Buffer.from(bytes).toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
