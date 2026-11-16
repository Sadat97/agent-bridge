// The small part of MLS (RFC 9420) the relay is allowed to read: the
// unencrypted framing header of an MLSMessage, the outer shape of a Welcome,
// and the public fields of a KeyPackage. No keys are involved.

import { createHash } from 'node:crypto';
import { utf8 } from './bytes.ts';
import { DecodeError, TlsReader, TlsWriter } from './tls.ts';

export const MLS_VERSION_10 = 1;

/** MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 — the only suite in v1. */
export const CIPHERSUITE_V1 = 1;

export const WireFormat = {
  public_message: 1,
  private_message: 2,
  welcome: 3,
  group_info: 4,
  key_package: 5,
} as const;
export type WireFormatName = keyof typeof WireFormat;

export const ContentType = { application: 1, proposal: 2, commit: 3 } as const;
export type ContentTypeName = keyof typeof ContentType;

const wireFormatNames = new Map<number, WireFormatName>(
  Object.entries(WireFormat).map(([name, value]) => [value, name as WireFormatName]),
);
const contentTypeNames = new Map<number, ContentTypeName>(
  Object.entries(ContentType).map(([name, value]) => [value, name as ContentTypeName]),
);

function readMessagePrefix(r: TlsReader): WireFormatName {
  const version = r.u16();
  if (version !== MLS_VERSION_10) throw new DecodeError(`unsupported MLS version ${version}`);
  const wireFormat = wireFormatNames.get(r.u16());
  if (wireFormat === undefined) throw new DecodeError('unknown wire format');
  return wireFormat;
}

export interface PrivateMessageHeader {
  wireFormat: 'private_message';
  groupId: Uint8Array;
  epoch: bigint;
  contentType: ContentTypeName;
  /**
   * Sent in the clear but bound into the AEAD: it is authentic only once the
   * message has been decrypted successfully. For a commit it carries the
   * membership approvals that bridges check (DESIGN.md section 5.8).
   */
  authenticatedData: Uint8Array;
}

export type MlsMessageHeader = PrivateMessageHeader | { wireFormat: Exclude<WireFormatName, 'private_message'> };

/**
 * Decodes an MLSMessage far enough to route it. For a PrivateMessage this is
 * group_id, epoch and content_type, which RFC 9420 leaves unencrypted; the
 * rest of the structure is checked for well-formedness but not interpreted.
 */
export function decodeMlsMessageHeader(message: Uint8Array): MlsMessageHeader {
  const r = new TlsReader(message);
  const wireFormat = readMessagePrefix(r);
  if (wireFormat !== 'private_message') return { wireFormat };

  const groupId = r.opaque();
  const epoch = r.u64();
  const contentType = contentTypeNames.get(r.u8());
  if (contentType === undefined) throw new DecodeError('unknown content type');
  const authenticatedData = r.opaque();
  r.opaque(); // encrypted_sender_data
  r.opaque(); // ciphertext
  r.end();
  return { wireFormat, groupId, epoch, contentType, authenticatedData };
}

export interface WelcomeSummary {
  cipherSuite: number;
}

/** Checks that `message` is an MLSMessage carrying a Welcome. */
export function decodeWelcomeMessage(message: Uint8Array): WelcomeSummary {
  const r = new TlsReader(message);
  if (readMessagePrefix(r) !== 'welcome') throw new DecodeError('not a Welcome');
  const cipherSuite = r.u16();
  r.opaque(); // secrets
  r.opaque(); // encrypted_group_info
  r.end();
  return { cipherSuite };
}

export interface KeyPackageSummary {
  cipherSuite: number;
  /** The leaf's signature public key. Must equal the uploading device's key. */
  signatureKey: Uint8Array;
  /** The encoded KeyPackage, without the MLSMessage prefix. */
  keyPackage: Uint8Array;
}

/** Reads the public fields of an MLSMessage carrying a KeyPackage. */
export function decodeKeyPackageMessage(message: Uint8Array): KeyPackageSummary {
  const r = new TlsReader(message);
  if (readMessagePrefix(r) !== 'key_package') throw new DecodeError('not a KeyPackage');
  const keyPackage = r.rest();
  const version = r.u16();
  if (version !== MLS_VERSION_10) throw new DecodeError(`unsupported KeyPackage version ${version}`);
  const cipherSuite = r.u16();
  r.opaque(); // init_key
  r.opaque(); // leaf_node.encryption_key
  const signatureKey = r.opaque();
  return { cipherSuite, signatureKey, keyPackage };
}

/**
 * KeyPackageRef = RefHash("MLS 1.0 KeyPackage Reference", KeyPackage)
 * (RFC 9420 section 5.2), using SHA-256 as cipher suite 1 does.
 */
export function keyPackageRef(keyPackage: Uint8Array): Uint8Array {
  const input = new TlsWriter().opaque(utf8('MLS 1.0 KeyPackage Reference')).opaque(keyPackage).finish();
  return new Uint8Array(createHash('sha256').update(input).digest());
}
