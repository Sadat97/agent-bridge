// Signature formats (DESIGN.md section 8.5).
//
// Every signature is Ed25519 over
//
//   struct {
//     opaque label<V>;    // "agent-bridge/v1/" + label
//     opaque content<V>;  // the TLS-encoded struct for that label
//   } SignContent;
//
// mirroring MLS's SignWithLabel, so a signature for one purpose can never be
// replayed as another. Times are uint64 Unix seconds; UUIDs are 16 raw bytes.

import { bytesToUuid, concatBytes, fromUtf8, utf8, uuidToBytes } from './bytes.ts';
import { ed25519Sign, ed25519Verify } from './ed25519.ts';
import { DecodeError, TlsReader, TlsWriter } from './tls.ts';

export const LABEL_PREFIX = 'agent-bridge/v1/';

export const SignatureLabel = {
  deviceCert: 'device-cert',
  add: 'add',
  remove: 'remove',
  request: 'request',
  state: 'state',
  relayAuth: 'relay-auth',
} as const;
export type SignatureLabel = (typeof SignatureLabel)[keyof typeof SignatureLabel];

export function signContent(label: SignatureLabel, content: Uint8Array): Uint8Array {
  return new TlsWriter().opaque(utf8(LABEL_PREFIX + label)).opaque(content).finish();
}

export function signWithLabel(privateKey: Uint8Array, label: SignatureLabel, content: Uint8Array): Uint8Array {
  return ed25519Sign(privateKey, signContent(label, content));
}

export function verifyWithLabel(
  publicKey: Uint8Array,
  label: SignatureLabel,
  content: Uint8Array,
  signature: Uint8Array,
): boolean {
  return ed25519Verify(publicKey, signContent(label, content), signature);
}

// ---------------------------------------------------------------------------
// Device certificate: the identity key vouches for a bridge's device key.
//
//   struct {
//     opaque handle<V>;
//     opaque device_id<V>;       // 16 bytes
//     opaque signature_key<V>;   // device Ed25519 public key
//     uint64 created_at;
//     opaque signature<V>;       // identity key, label "device-cert", over the fields above
//   } DeviceCert;

export interface DeviceCertFields {
  handle: string;
  deviceId: string;
  signatureKey: Uint8Array;
  createdAt: number;
}

function encodeDeviceCertTbs(fields: DeviceCertFields): Uint8Array {
  return new TlsWriter()
    .opaque(utf8(fields.handle))
    .opaque(uuidToBytes(fields.deviceId))
    .opaque(fields.signatureKey)
    .u64(fields.createdAt)
    .finish();
}

export function issueDeviceCert(identityPrivateKey: Uint8Array, fields: DeviceCertFields): Uint8Array {
  const tbs = encodeDeviceCertTbs(fields);
  const signature = signWithLabel(identityPrivateKey, SignatureLabel.deviceCert, tbs);
  return concatBytes(tbs, new TlsWriter().opaque(signature).finish());
}

export interface DecodedDeviceCert extends DeviceCertFields {
  signature: Uint8Array;
}

export function decodeDeviceCert(cert: Uint8Array): DecodedDeviceCert {
  const r = new TlsReader(cert);
  const handle = fromUtf8(r.opaque());
  const deviceIdBytes = r.opaque();
  if (deviceIdBytes.length !== 16) throw new DecodeError('device_id must be 16 bytes');
  const signatureKey = r.opaque();
  const createdAt = r.u64();
  const signature = r.opaque();
  r.end();
  if (createdAt > BigInt(Number.MAX_SAFE_INTEGER)) throw new DecodeError('created_at out of range');
  return { handle, deviceId: bytesToUuid(deviceIdBytes), signatureKey, createdAt: Number(createdAt), signature };
}

/** Returns the certified fields, or null if the certificate is malformed or not signed by `identityKey`. */
export function verifyDeviceCert(cert: Uint8Array, identityKey: Uint8Array): DecodedDeviceCert | null {
  let decoded: DecodedDeviceCert;
  try {
    decoded = decodeDeviceCert(cert);
  } catch {
    return null;
  }
  const ok = verifyWithLabel(identityKey, SignatureLabel.deviceCert, encodeDeviceCertTbs(decoded), decoded.signature);
  return ok ? decoded : null;
}

// ---------------------------------------------------------------------------
// Membership approvals, signed by the topic owner's identity key.

export const MemberRole = { member: 1, owner: 2 } as const;
export type MemberRoleName = keyof typeof MemberRole;

export interface AddApproval {
  topicId: string;
  approvalId: string;
  inviteeIdentityKey: Uint8Array;
  inviteeDeviceKey: Uint8Array;
  role: MemberRoleName;
  /** Unix seconds. */
  expiresAt: number;
}

export function addApprovalContent(a: AddApproval): Uint8Array {
  return new TlsWriter()
    .opaque(uuidToBytes(a.topicId))
    .opaque(utf8(a.approvalId))
    .opaque(a.inviteeIdentityKey)
    .opaque(a.inviteeDeviceKey)
    .u8(MemberRole[a.role])
    .u64(a.expiresAt)
    .finish();
}

export interface RemoveApproval {
  topicId: string;
  approvalId: string;
  removedDeviceKey: Uint8Array;
}

export function removeApprovalContent(a: RemoveApproval): Uint8Array {
  return new TlsWriter()
    .opaque(uuidToBytes(a.topicId))
    .opaque(utf8(a.approvalId))
    .opaque(a.removedDeviceKey)
    .finish();
}

// ---------------------------------------------------------------------------
// Approved requests and state changes, signed by the author's identity key.

export interface RequestApproval {
  topicId: string;
  messageId: string;
  /** SHA-256 of the envelope without its `approval` field. */
  envelopeHash: Uint8Array;
}

export function requestApprovalContent(a: RequestApproval): Uint8Array {
  return new TlsWriter().opaque(uuidToBytes(a.topicId)).opaque(utf8(a.messageId)).opaque(a.envelopeHash).finish();
}

export interface StateApproval {
  topicId: string;
  baseVersion: number;
  baseHash: Uint8Array;
  /** SHA-256 of the canonical (RFC 8785) patch. */
  patchHash: Uint8Array;
}

export function stateApprovalContent(a: StateApproval): Uint8Array {
  return new TlsWriter()
    .opaque(uuidToBytes(a.topicId))
    .u64(a.baseVersion)
    .opaque(a.baseHash)
    .opaque(a.patchHash)
    .finish();
}

// ---------------------------------------------------------------------------
// Relay login, signed by the device key.

export function relayAuthContent(relayOrigin: string, nonce: Uint8Array): Uint8Array {
  return new TlsWriter().opaque(utf8(relayOrigin)).opaque(nonce).finish();
}
