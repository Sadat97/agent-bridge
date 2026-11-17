// At-rest wrapping. See DESIGN.md section 4.2.
//
// `storage.key` (mode 0600) is 32 random bytes. It seals the device private
// key, MLS state, staged MLS state, and KeyPackage private material with
// AES-256-GCM. Associated data binds a ciphertext to the row it belongs to,
// so a blob copied onto another row does not open.
//
// The identity private key is not under that key. A passphrase is stretched
// with Argon2id and the seed is sealed with a fresh salt and nonce. The daemon
// opens it for one approval and then zeroes the seed. Message plaintext and
// the shared-state document stay unencrypted; those rely on OS disk encryption.

import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { argon2id } from '@noble/hashes/argon2.js';
import type { SecretSealer } from '@agent-bridge/mls';
import { BridgeError } from './errors.ts';

const STORAGE_VERSION = 1;
const PASSPHRASE_VERSION = 2;

/** RFC 9106 second recommended option, the OWASP minimum for Argon2id. */
export const ARGON2_TIME = 2;
export const ARGON2_MEMORY_KIB = 19_456;
export const ARGON2_PARALLELISM = 1;

export function randomStorageKey(): Uint8Array {
  return randomBytes(32);
}

export class AesGcmSealer implements SecretSealer {
  readonly #key: Buffer;

  constructor(key: Uint8Array) {
    if (key.length !== 32) throw new Error('storage key must be 32 bytes');
    this.#key = Buffer.from(key);
  }

  seal(plaintext: Uint8Array, aad: Uint8Array): Uint8Array {
    const nonce = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.#key, nonce);
    cipher.setAAD(Buffer.from(aad));
    const body = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
    const out = new Uint8Array(1 + nonce.length + body.length);
    out[0] = STORAGE_VERSION;
    out.set(nonce, 1);
    out.set(body, 1 + nonce.length);
    return out;
  }

  open(sealed: Uint8Array, aad: Uint8Array): Uint8Array {
    if (sealed.length < 1 + 12 + 16 || sealed[0] !== STORAGE_VERSION) {
      throw new BridgeError('mls_error', 'stored secret could not be opened', 500);
    }
    try {
      const nonce = sealed.subarray(1, 13);
      const tag = sealed.subarray(sealed.length - 16);
      const data = sealed.subarray(13, sealed.length - 16);
      const decipher = createDecipheriv('aes-256-gcm', this.#key, nonce);
      decipher.setAAD(Buffer.from(aad));
      decipher.setAuthTag(Buffer.from(tag));
      return new Uint8Array(Buffer.concat([decipher.update(data), decipher.final()]));
    } catch (err) {
      if (err instanceof BridgeError) throw err;
      throw new BridgeError('mls_error', 'stored secret could not be opened', 500);
    }
  }
}

export function wrapPassphrase(secret: Uint8Array, passphrase: string, aad: Uint8Array): Uint8Array {
  const salt = randomBytes(16);
  const key = derive(passphrase, salt, ARGON2_TIME, ARGON2_MEMORY_KIB, ARGON2_PARALLELISM);
  try {
    const nonce = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, nonce);
    cipher.setAAD(Buffer.from(aad));
    const body = Buffer.concat([cipher.update(secret), cipher.final(), cipher.getAuthTag()]);
    const header = Buffer.alloc(1 + 16 + 4 + 4 + 1);
    header[0] = PASSPHRASE_VERSION;
    header.set(salt, 1);
    header.writeUInt32BE(ARGON2_TIME, 17);
    header.writeUInt32BE(ARGON2_MEMORY_KIB, 21);
    header[25] = ARGON2_PARALLELISM;
    return new Uint8Array(Buffer.concat([header, nonce, body]));
  } finally {
    key.fill(0);
  }
}

export function unwrapPassphrase(sealed: Uint8Array, passphrase: string, aad: Uint8Array): Uint8Array {
  if (sealed.length < 26 + 12 + 16 || sealed[0] !== PASSPHRASE_VERSION) {
    throw new BridgeError('invalid_passphrase', 'identity passphrase is not valid', 401);
  }
  const salt = sealed.subarray(1, 17);
  const time = readU32(sealed, 17);
  const memory = readU32(sealed, 21);
  const parallelism = sealed[25] ?? 0;
  if (parallelism < 1) throw new BridgeError('invalid_passphrase', 'identity passphrase is not valid', 401);
  const key = derive(passphrase, salt, time, memory, parallelism);
  try {
    const nonce = sealed.subarray(26, 38);
    const tag = sealed.subarray(sealed.length - 16);
    const data = sealed.subarray(38, sealed.length - 16);
    const decipher = createDecipheriv('aes-256-gcm', key, nonce);
    decipher.setAAD(Buffer.from(aad));
    decipher.setAuthTag(Buffer.from(tag));
    return new Uint8Array(Buffer.concat([decipher.update(data), decipher.final()]));
  } catch {
    throw new BridgeError('invalid_passphrase', 'identity passphrase is not valid', 401);
  } finally {
    key.fill(0);
  }
}

function derive(passphrase: string, salt: Uint8Array, time: number, memory: number, parallelism: number): Buffer {
  return Buffer.from(argon2id(passphrase, salt, { t: time, m: memory, p: parallelism, dkLen: 32 }));
}

function readU32(bytes: Uint8Array, offset: number): number {
  return Buffer.from(bytes.buffer, bytes.byteOffset + offset, 4).readUInt32BE(0);
}
