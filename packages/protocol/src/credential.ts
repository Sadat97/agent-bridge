// BridgeCredential: the bytes in MLS BasicCredential.identity (DESIGN.md 8.2).
//
// struct {
//   opaque handle<V>;
//   opaque identity_pubkey<V>;   // 32-byte Ed25519
//   opaque device_id<V>;         // 16 raw bytes
//   opaque device_cert<V>;
// } BridgeCredential;
//
// Handles use the relay's registration pattern so a credential can only name
// an account the relay would actually store.

import { bytesEqual, bytesToUuid, fromUtf8, utf8, uuidToBytes } from './bytes.ts';
import { ED25519_PUBLIC_KEY_LENGTH } from './ed25519.ts';
import { verifyDeviceCert } from './signatures.ts';
import type { DecodedDeviceCert } from './signatures.ts';
import { DecodeError, TlsReader, TlsWriter } from './tls.ts';

/** Same pattern the relay enforces on `POST /v1/accounts`. */
export const HANDLE_PATTERN = /^[a-z0-9][a-z0-9_-]{1,31}$/;

export interface BridgeCredential {
  handle: string;
  /** 32-byte Ed25519 identity public key. */
  identityKey: Uint8Array;
  deviceId: string;
  deviceCert: Uint8Array;
}

export function encodeBridgeCredential(credential: BridgeCredential): Uint8Array {
  if (!HANDLE_PATTERN.test(credential.handle)) throw new TypeError('handle is not a relay handle');
  if (credential.identityKey.length !== ED25519_PUBLIC_KEY_LENGTH) {
    throw new TypeError('identity key must be 32 bytes');
  }
  return new TlsWriter()
    .opaque(utf8(credential.handle))
    .opaque(credential.identityKey)
    .opaque(uuidToBytes(credential.deviceId))
    .opaque(credential.deviceCert)
    .finish();
}

export function decodeBridgeCredential(bytes: Uint8Array): BridgeCredential {
  const r = new TlsReader(bytes);
  const handle = fromUtf8(r.opaque());
  if (!HANDLE_PATTERN.test(handle)) throw new DecodeError('handle is not a relay handle');
  const identityKey = r.opaque();
  if (identityKey.length !== ED25519_PUBLIC_KEY_LENGTH) throw new DecodeError('identity key must be 32 bytes');
  const deviceId = r.opaque();
  if (deviceId.length !== 16) throw new DecodeError('device_id must be 16 bytes');
  const deviceCert = r.opaque();
  r.end();
  return { handle, identityKey, deviceId: bytesToUuid(deviceId), deviceCert };
}

export interface LeafCredential {
  credential: BridgeCredential;
  cert: DecodedDeviceCert;
}

export type LeafCredentialCheck =
  | { ok: true; leaf: LeafCredential }
  | { ok: false; reason: string };

/**
 * Section 8.2 for one leaf. `pinnedIdentityKey`, when present, is the key this
 * bridge already stored for the credential's handle; a difference is a hard
 * failure (TOFU, section 8.3). Omitting it skips the pin check.
 */
export function validateLeafCredential(
  identity: Uint8Array,
  signatureKey: Uint8Array,
  pinnedIdentityKey?: Uint8Array,
): LeafCredentialCheck {
  let credential: BridgeCredential;
  try {
    credential = decodeBridgeCredential(identity);
  } catch {
    return { ok: false, reason: 'credential is not a BridgeCredential' };
  }
  const cert = verifyDeviceCert(credential.deviceCert, credential.identityKey);
  if (!cert) return { ok: false, reason: 'device certificate does not verify under the credential identity key' };
  if (cert.handle !== credential.handle) return { ok: false, reason: 'device certificate is for a different handle' };
  if (cert.deviceId !== credential.deviceId) return { ok: false, reason: 'device certificate is for a different device' };
  if (!bytesEqual(cert.signatureKey, signatureKey)) {
    return { ok: false, reason: 'device certificate key does not match the leaf signature key' };
  }
  if (pinnedIdentityKey !== undefined && !bytesEqual(pinnedIdentityKey, credential.identityKey)) {
    return { ok: false, reason: 'identity key does not match the pinned contact' };
  }
  return { ok: true, leaf: { credential, cert } };
}
