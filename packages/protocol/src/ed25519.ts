import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';
import type { KeyObject } from 'node:crypto';

// Raw key formats: a public key is 32 bytes; a private key is the 32-byte seed.
// This matches what ts-mls accepts for Ed25519 signature keys.

const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

export const ED25519_PUBLIC_KEY_LENGTH = 32;
export const ED25519_SIGNATURE_LENGTH = 64;

export interface Ed25519KeyPair {
  publicKey: Uint8Array;
  /** 32-byte seed. */
  privateKey: Uint8Array;
}

function privateKeyObject(seed: Uint8Array): KeyObject {
  if (seed.length !== 32) throw new TypeError('Ed25519 private key must be a 32-byte seed');
  return createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, seed]), format: 'der', type: 'pkcs8' });
}

function publicKeyObject(publicKey: Uint8Array): KeyObject {
  return createPublicKey({ key: Buffer.concat([SPKI_PREFIX, publicKey]), format: 'der', type: 'spki' });
}

export function generateEd25519KeyPair(): Ed25519KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    publicKey: new Uint8Array(publicKey.export({ format: 'der', type: 'spki' }).subarray(SPKI_PREFIX.length)),
    privateKey: new Uint8Array(privateKey.export({ format: 'der', type: 'pkcs8' }).subarray(PKCS8_PREFIX.length)),
  };
}

export function ed25519PublicKeyFromSeed(seed: Uint8Array): Uint8Array {
  const pub = createPublicKey(privateKeyObject(seed));
  return new Uint8Array(pub.export({ format: 'der', type: 'spki' }).subarray(SPKI_PREFIX.length));
}

export function ed25519Sign(seed: Uint8Array, message: Uint8Array): Uint8Array {
  return new Uint8Array(sign(null, message, privateKeyObject(seed)));
}

/** Never throws: malformed keys or signatures verify as false. */
export function ed25519Verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  if (publicKey.length !== ED25519_PUBLIC_KEY_LENGTH || signature.length !== ED25519_SIGNATURE_LENGTH) return false;
  try {
    return verify(null, message, publicKeyObject(publicKey), signature);
  } catch {
    return false;
  }
}
