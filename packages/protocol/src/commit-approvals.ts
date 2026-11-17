// CommitApprovals: the authenticated_data of a commit that adds or removes
// members (DESIGN.md section 5.8). A commit with no Add or Remove carries
// empty authenticated_data instead of an empty CommitApprovals struct.
//
// struct {
//   opaque approval_id<V>;
//   opaque device_key<V>;
//   uint64 expires_at;
//   opaque signature<V>;
// } AddApprovalEntry;
//
// struct {
//   opaque approval_id<V>;
//   opaque device_key<V>;
//   uint8 kind;                    // 1 = remove, 2 = leave
//   select (kind) {
//     case 1: opaque signature<V>;
//     case 2: uint64 leave_seq;
//   };
// } RemoveApprovalEntry;
//
// struct {
//   uint8 version = 1;
//   AddApprovalEntry adds<V>;
//   RemoveApprovalEntry removes<V>;
// } CommitApprovals;

import { concatBytes, fromUtf8, utf8 } from './bytes.ts';
import { DecodeError, TlsReader, TlsWriter } from './tls.ts';

export const COMMIT_APPROVALS_VERSION = 1;
export const REMOVE_KIND = 1;
export const LEAVE_KIND = 2;

/** Same pattern the relay enforces on membership approval ids. */
export const APPROVAL_ID_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;

export interface AddApprovalEntry {
  approvalId: string;
  /** The added leaf's signature public key. */
  deviceKey: Uint8Array;
  /** Unix seconds. Bound into the signature; receivers do not re-check it. */
  expiresAt: number;
  /** Topic-owner identity key, label "add". */
  signature: Uint8Array;
}

export interface RemoveSignatureEntry {
  kind: 'remove';
  approvalId: string;
  /** The removed leaf's signature public key. */
  deviceKey: Uint8Array;
  /** Topic-owner identity key, label "remove". */
  signature: Uint8Array;
}

export interface LeaveEntry {
  kind: 'leave';
  approvalId: string;
  deviceKey: Uint8Array;
  /** Relay seq of the member's own leave message. */
  leaveSeq: number;
}

export type RemoveApprovalEntry = RemoveSignatureEntry | LeaveEntry;

export interface CommitApprovals {
  adds: AddApprovalEntry[];
  removes: RemoveApprovalEntry[];
}

function u64(r: TlsReader): number {
  const value = r.u64();
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw new DecodeError('integer out of range');
  return Number(value);
}

function encodeAdd(entry: AddApprovalEntry): Uint8Array {
  return new TlsWriter().opaque(utf8(entry.approvalId)).opaque(entry.deviceKey).u64(entry.expiresAt).opaque(entry.signature).finish();
}

function encodeRemove(entry: RemoveApprovalEntry): Uint8Array {
  const w = new TlsWriter().opaque(utf8(entry.approvalId)).opaque(entry.deviceKey);
  if (entry.kind === 'remove') return w.u8(REMOVE_KIND).opaque(entry.signature).finish();
  return w.u8(LEAVE_KIND).u64(entry.leaveSeq).finish();
}

export function encodeCommitApprovals(approvals: CommitApprovals): Uint8Array {
  const adds = concatBytes(...approvals.adds.map(encodeAdd));
  const removes = concatBytes(...approvals.removes.map(encodeRemove));
  return new TlsWriter().u8(COMMIT_APPROVALS_VERSION).opaque(adds).opaque(removes).finish();
}

function decodeAdd(r: TlsReader): AddApprovalEntry {
  return { approvalId: fromUtf8(r.opaque()), deviceKey: r.opaque(), expiresAt: u64(r), signature: r.opaque() };
}

function decodeRemove(r: TlsReader): RemoveApprovalEntry {
  const approvalId = fromUtf8(r.opaque());
  const deviceKey = r.opaque();
  const kind = r.u8();
  if (kind === REMOVE_KIND) return { kind: 'remove', approvalId, deviceKey, signature: r.opaque() };
  if (kind === LEAVE_KIND) return { kind: 'leave', approvalId, deviceKey, leaveSeq: u64(r) };
  throw new DecodeError(`unknown remove approval kind ${kind}`);
}

function decodeList<T>(bytes: Uint8Array, decodeOne: (r: TlsReader) => T): T[] {
  const r = new TlsReader(bytes);
  const out: T[] = [];
  while (r.remaining > 0) out.push(decodeOne(r));
  return out;
}

export function decodeCommitApprovals(bytes: Uint8Array): CommitApprovals {
  const r = new TlsReader(bytes);
  const version = r.u8();
  if (version !== COMMIT_APPROVALS_VERSION) throw new DecodeError(`unsupported CommitApprovals version ${version}`);
  const adds = decodeList(r.opaque(), decodeAdd);
  const removes = decodeList(r.opaque(), decodeRemove);
  r.end();
  return { adds, removes };
}
