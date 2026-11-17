// Application-message JSON (DESIGN.md section 5.2). Parsing is strict enough
// to recognise a leave and loose enough that a malformed body is dropped
// instead of throwing: the MLS ratchet still has to advance.

import { fromUtf8, utf8 } from '@agent-bridge/protocol';

export const MESSAGE_TYPES = [
  'update',
  'question',
  'request',
  'answer',
  'state_patch',
  'state_snapshot',
  'snapshot_request',
  'invite_proposal',
  'removal_proposal',
  'leave',
  'system',
] as const;

export type MessageType = (typeof MESSAGE_TYPES)[number];

const MESSAGE_TYPE_SET: ReadonlySet<string> = new Set(MESSAGE_TYPES);

export interface Envelope {
  v: 1;
  id: string;
  type: MessageType;
  ts: string;
  author: { handle: string; agent?: string };
  reply_to: string | null;
  body?: string;
  payload: Record<string, unknown>;
  approval: { sig: string } | null;
}

export function encodeEnvelope(envelope: Envelope): Uint8Array {
  return utf8(JSON.stringify(envelope));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Returns null when the bytes are not an envelope this bridge will act on. */
export function parseEnvelope(bytes: Uint8Array): Envelope | null {
  let value: unknown;
  try {
    value = JSON.parse(fromUtf8(bytes));
  } catch {
    return null;
  }
  if (!isRecord(value)) return null;
  if (value.v !== 1 || typeof value.id !== 'string' || value.id.length === 0) return null;
  if (typeof value.type !== 'string' || !MESSAGE_TYPE_SET.has(value.type)) return null;
  if (typeof value.ts !== 'string') return null;
  if (!isRecord(value.author) || typeof value.author.handle !== 'string') return null;
  if (value.author.agent !== undefined && typeof value.author.agent !== 'string') return null;
  if (value.reply_to !== undefined && value.reply_to !== null && typeof value.reply_to !== 'string') return null;
  if (value.body !== undefined && typeof value.body !== 'string') return null;
  if (value.payload !== undefined && !isRecord(value.payload)) return null;
  if (value.approval !== undefined && value.approval !== null) {
    if (!isRecord(value.approval) || typeof value.approval.sig !== 'string') return null;
  }
  const author: Envelope['author'] = { handle: value.author.handle };
  if (typeof value.author.agent === 'string') author.agent = value.author.agent;
  const envelope: Envelope = {
    v: 1,
    id: value.id,
    type: value.type as MessageType,
    ts: value.ts,
    author,
    reply_to: typeof value.reply_to === 'string' ? value.reply_to : null,
    payload: isRecord(value.payload) ? value.payload : {},
    approval: isRecord(value.approval) && typeof value.approval.sig === 'string' ? { sig: value.approval.sig } : null,
  };
  if (typeof value.body === 'string') envelope.body = value.body;
  return envelope;
}
