// Identity-key signatures on requests and state changes (DESIGN.md section 8.5).
// The signed bytes are the canonical envelope or patch, so key order on the
// wire does not matter.

import {
  SignatureLabel,
  requestApprovalContent,
  signWithLabel,
  stateApprovalContent,
  verifyWithLabel,
} from '@agent-bridge/protocol';
import type { Envelope } from '@agent-bridge/mls';
import { hashBytes, parseHashLabel } from './json.ts';

export function unsignedEnvelope(envelope: Envelope): Record<string, unknown> {
  const unsigned: Record<string, unknown> = {
    v: envelope.v,
    id: envelope.id,
    type: envelope.type,
    ts: envelope.ts,
    author: envelope.author,
    reply_to: envelope.reply_to,
    payload: envelope.payload,
    approval: null,
  };
  if (envelope.body !== undefined) unsigned.body = envelope.body;
  return unsigned;
}

export function signRequest(privateKey: Uint8Array, topicId: string, envelope: Envelope): Uint8Array {
  return signWithLabel(
    privateKey,
    SignatureLabel.request,
    requestApprovalContent({ topicId, messageId: envelope.id, envelopeHash: hashBytes(unsignedEnvelope(envelope)) }),
  );
}

export function verifyRequest(topicId: string, envelope: Envelope, identityKey: Uint8Array, signature: Uint8Array): boolean {
  return verifyWithLabel(
    identityKey,
    SignatureLabel.request,
    requestApprovalContent({ topicId, messageId: envelope.id, envelopeHash: hashBytes(unsignedEnvelope(envelope)) }),
    signature,
  );
}

export function signState(
  privateKey: Uint8Array,
  topicId: string,
  baseVersion: number,
  baseHash: Uint8Array,
  patch: unknown,
): Uint8Array {
  return signWithLabel(
    privateKey,
    SignatureLabel.state,
    stateApprovalContent({ topicId, baseVersion, baseHash, patchHash: hashBytes(patch) }),
  );
}

export function verifyState(topicId: string, envelope: Envelope, identityKey: Uint8Array, signature: Uint8Array): boolean {
  const version = envelope.payload.base_version;
  const hash = typeof envelope.payload.base_hash === 'string' ? parseHashLabel(envelope.payload.base_hash) : undefined;
  if (typeof version !== 'number' || hash === undefined) return false;
  return verifyWithLabel(
    identityKey,
    SignatureLabel.state,
    stateApprovalContent({ topicId, baseVersion: version, baseHash: hash, patchHash: hashBytes(envelope.payload.patch) }),
    signature,
  );
}
