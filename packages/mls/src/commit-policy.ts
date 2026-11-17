// Bridge-side commit policy (DESIGN.md section 5.8). Pure and synchronous so it
// can run inside ts-mls's commit callback, after decryption and before apply.
//
// The relay accepts any application message from the removed device as a
// leave_seq. This check does not: the cited seq must be a `leave` envelope
// this bridge decrypted from that same member.

import {
  addApprovalContent,
  APPROVAL_ID_PATTERN,
  bytesEqual,
  decodeCommitApprovals,
  encodeBridgeCredential,
  removeApprovalContent,
  SignatureLabel,
  toBase64,
  validateLeafCredential,
  verifyWithLabel,
} from '@agent-bridge/protocol';
import type { CommitInspection, Member, ProposalSummary } from './types.ts';

export interface RecordedMessage {
  signatureKey: Uint8Array;
  type: string;
  /** False when author.handle did not match the sender credential. */
  authorMatches: boolean;
}

export interface CommitPolicyContext {
  topicId: string;
  ownerIdentityKey: Uint8Array;
  consumedApprovalIds: ReadonlySet<string>;
  /** Application messages this bridge has already processed, keyed by relay seq. */
  messages: ReadonlyMap<number, RecordedMessage>;
  pinnedIdentity(handle: string): Uint8Array | undefined;
}

export type CommitDecision =
  | { ok: true; approvalIds: string[]; pins: Array<{ handle: string; identityKey: Uint8Array }> }
  | { ok: false; reason: string };

const MEMBERSHIP_PROPOSALS: ReadonlySet<ProposalSummary['kind']> = new Set(['add', 'remove', 'update']);

function reject(reason: string): CommitDecision {
  return { ok: false, reason };
}

function indexByDeviceKey<T extends { deviceKey: Uint8Array }>(entries: T[]): Map<string, T> | null {
  const map = new Map<string, T>();
  for (const entry of entries) {
    const key = toBase64(entry.deviceKey);
    if (map.has(key)) return null;
    map.set(key, entry);
  }
  return map;
}

export function evaluateCommit(commit: CommitInspection, ctx: CommitPolicyContext): CommitDecision {
  for (const proposal of commit.proposals) {
    if (!MEMBERSHIP_PROPOSALS.has(proposal.kind)) return reject(`unsupported proposal ${proposal.kind}`);
  }

  const adds = commit.proposals.flatMap((proposal) => (proposal.kind === 'add' ? [proposal] : []));
  const removes = commit.proposals.flatMap((proposal) => (proposal.kind === 'remove' ? [proposal] : []));
  if (adds.length + removes.length === 0) {
    if (commit.authenticatedData.length !== 0) {
      return reject('authenticated data must be empty when the commit does not add or remove');
    }
    return { ok: true, approvalIds: [], pins: [] };
  }

  if (!bytesEqual(commit.committer.credential.identityKey, ctx.ownerIdentityKey)) {
    return reject('committer is not the topic owner');
  }
  for (const proposal of removes) {
    if (!proposal.removed) return reject('remove proposal does not name a current member');
    if (bytesEqual(proposal.removed.credential.identityKey, ctx.ownerIdentityKey)) {
      return reject('remove targets the topic owner');
    }
  }

  let approvals;
  try {
    approvals = decodeCommitApprovals(commit.authenticatedData);
  } catch {
    return reject('authenticated data is not CommitApprovals');
  }
  if (approvals.adds.length !== adds.length || approvals.removes.length !== removes.length) {
    return reject('approvals do not match the commit');
  }
  const addEntries = indexByDeviceKey(approvals.adds);
  const removeEntries = indexByDeviceKey(approvals.removes);
  if (!addEntries || !removeEntries) return reject('approvals do not match the commit');

  const seen = new Set<string>();
  const approvalIds: string[] = [];
  const pins: Array<{ handle: string; identityKey: Uint8Array }> = [];

  for (const proposal of adds) {
    const added = proposal.added;
    if (!added) return reject('credential is invalid');
    const entry = addEntries.get(toBase64(added.signatureKey));
    if (!entry || !bytesEqual(entry.deviceKey, added.signatureKey)) return reject('approvals do not match the commit');
    const idError = claimApprovalId(entry.approvalId, seen, ctx);
    if (idError) return idError;
    const content = addApprovalContent({
      topicId: ctx.topicId,
      approvalId: entry.approvalId,
      inviteeIdentityKey: added.credential.identityKey,
      inviteeDeviceKey: entry.deviceKey,
      role: 'member',
      expiresAt: entry.expiresAt,
    });
    if (!verifyWithLabel(ctx.ownerIdentityKey, SignatureLabel.add, content, entry.signature)) {
      return reject('approval signature is invalid');
    }
    const credentialError = checkNewLeaf(added, ctx, pins);
    if (credentialError) return credentialError;
    approvalIds.push(entry.approvalId);
  }

  for (const proposal of removes) {
    const removed = proposal.removed;
    if (!removed) return reject('remove proposal does not name a current member');
    const entry = removeEntries.get(toBase64(removed.signatureKey));
    if (!entry || !bytesEqual(entry.deviceKey, removed.signatureKey)) return reject('approvals do not match the commit');
    const idError = claimApprovalId(entry.approvalId, seen, ctx);
    if (idError) return idError;
    if (entry.kind === 'remove') {
      const content = removeApprovalContent({
        topicId: ctx.topicId,
        approvalId: entry.approvalId,
        removedDeviceKey: entry.deviceKey,
      });
      if (!verifyWithLabel(ctx.ownerIdentityKey, SignatureLabel.remove, content, entry.signature)) {
        return reject('approval signature is invalid');
      }
    } else {
      const message = ctx.messages.get(entry.leaveSeq);
      if (!message || !bytesEqual(message.signatureKey, removed.signatureKey)) {
        return reject('leave_seq was not sent by the removed member');
      }
      // The relay treats any application message from that device as a leave.
      // A cited update, question, or any other type is not one.
      if (message.type !== 'leave' || !message.authorMatches) return reject('leave_seq is not a leave message');
    }
    approvalIds.push(entry.approvalId);
  }

  return { ok: true, approvalIds, pins };
}

function claimApprovalId(approvalId: string, seen: Set<string>, ctx: CommitPolicyContext): CommitDecision | null {
  if (!APPROVAL_ID_PATTERN.test(approvalId)) return reject('approval_id is invalid');
  if (seen.has(approvalId) || ctx.consumedApprovalIds.has(approvalId)) return reject('approval already used');
  seen.add(approvalId);
  return null;
}

function checkNewLeaf(
  added: Member,
  ctx: CommitPolicyContext,
  pins: Array<{ handle: string; identityKey: Uint8Array }>,
): CommitDecision | null {
  const pinned = ctx.pinnedIdentity(added.credential.handle);
  const check = validateLeafCredential(encodeBridgeCredential(added.credential), added.signatureKey, pinned);
  if (!check.ok) return reject('credential is invalid');
  if (pinned) return null;
  const earlier = pins.find((pin) => pin.handle === added.credential.handle);
  if (earlier && !bytesEqual(earlier.identityKey, added.credential.identityKey)) return reject('credential is invalid');
  if (!earlier) pins.push({ handle: added.credential.handle, identityKey: added.credential.identityKey });
  return null;
}
