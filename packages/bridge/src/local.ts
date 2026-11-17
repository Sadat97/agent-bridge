// Bridge rows that sit beside the MLS store in the same SQLite file.
// Plaintext messages and shared state are written here. Secrets are not:
// the MLS store seals those before they reach disk.

import { DatabaseSync } from 'node:sqlite';
import { bytesEqual } from '@agent-bridge/protocol';
import type { Envelope, PersistedFrame, StoreDb } from '@agent-bridge/mls';
import { applyPatch, hashBytes, parseHashLabel } from './json.ts';
import type { PatchOp } from './json.ts';
import { verifyRequest, verifyState } from './signatures.ts';

export interface TopicStateRow {
  version: number;
  hash: Uint8Array;
  doc: unknown;
  updatedSeq: number;
}

export interface EnvelopeRow {
  seq: number;
  messageId: string;
  authorHandle: string;
  authorAgent: string | null;
  type: string;
  body: string | null;
  payload: unknown;
  approvalOk: boolean;
  applied: boolean | null;
  ts: string;
}

export interface ApprovalRow {
  approvalId: string;
  topicId: string;
  kind: string;
  status: string;
  requestedBy: string;
  summary: string;
  request: unknown;
  createdAt: string;
  decidedAt: string | null;
}

export interface TokenRow {
  label: string;
  topics: '*' | string[];
  createdAt: string;
  revokedAt: string | null;
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS identity (
  handle TEXT PRIMARY KEY,
  identity_pubkey BLOB NOT NULL,
  identity_privkey BLOB NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS device (
  device_id TEXT PRIMARY KEY,
  signature_pubkey BLOB NOT NULL,
  signature_privkey BLOB NOT NULL,
  device_cert BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS agent_tokens (
  token_hash BLOB PRIMARY KEY,
  agent_label TEXT UNIQUE NOT NULL,
  topic_scope TEXT NOT NULL,
  created_at TEXT NOT NULL,
  revoked_at TEXT
);
CREATE TABLE IF NOT EXISTS read_cursors (
  agent_label TEXT NOT NULL,
  topic_id TEXT NOT NULL,
  last_read_seq INTEGER NOT NULL,
  PRIMARY KEY (agent_label, topic_id)
);
CREATE TABLE IF NOT EXISTS approvals (
  approval_id TEXT PRIMARY KEY,
  topic_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  status TEXT NOT NULL,
  requested_by TEXT NOT NULL,
  summary TEXT NOT NULL,
  request_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  decided_at TEXT
);
CREATE TABLE IF NOT EXISTS topic_state (
  topic_id TEXT PRIMARY KEY,
  version INTEGER NOT NULL,
  doc_hash BLOB NOT NULL,
  doc_json TEXT NOT NULL,
  updated_seq INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS envelopes (
  topic_id TEXT NOT NULL,
  seq INTEGER NOT NULL,
  message_id TEXT NOT NULL,
  author_handle TEXT NOT NULL,
  author_agent TEXT,
  type TEXT NOT NULL,
  body TEXT,
  payload_json TEXT NOT NULL,
  approval_ok INTEGER NOT NULL,
  applied INTEGER,
  ts TEXT NOT NULL,
  PRIMARY KEY (topic_id, seq)
);
CREATE TABLE IF NOT EXISTS member_seen (
  topic_id TEXT NOT NULL,
  handle TEXT NOT NULL,
  role TEXT NOT NULL,
  joined_at TEXT NOT NULL,
  removed_at TEXT,
  PRIMARY KEY (topic_id, handle)
);
`;

export class LocalStore {
  readonly db: DatabaseSync;

  constructor(path: string) {
    this.db = new DatabaseSync(path);
    this.db.exec('PRAGMA busy_timeout = 1000');
    this.db.exec(SCHEMA);
    const names = new Set(
      this.db
        .prepare('PRAGMA table_info(contacts)')
        .all()
        .map((row) => String(row.name)),
    );
    if (names.size > 0 && !names.has('verified_at')) {
      this.db.exec('ALTER TABLE contacts ADD COLUMN verified_at TEXT');
    }
  }

  close(): void {
    this.db.close();
  }

  saveIdentity(handle: string, publicKey: Uint8Array, wrappedPrivate: Uint8Array): void {
    this.db
      .prepare(
        `INSERT INTO identity (handle, identity_pubkey, identity_privkey, created_at) VALUES (?, ?, ?, ?)`,
      )
      .run(handle, publicKey, wrappedPrivate, new Date().toISOString());
  }

  identity(): { handle: string; publicKey: Uint8Array; wrappedPrivate: Uint8Array } | undefined {
    const row = this.db.prepare('SELECT handle, identity_pubkey, identity_privkey FROM identity').get();
    if (!row) return undefined;
    return {
      handle: String(row.handle),
      publicKey: bytes(row.identity_pubkey),
      wrappedPrivate: bytes(row.identity_privkey),
    };
  }

  saveDevice(deviceId: string, publicKey: Uint8Array, wrappedPrivate: Uint8Array, cert: Uint8Array): void {
    this.db
      .prepare(
        `INSERT INTO device (device_id, signature_pubkey, signature_privkey, device_cert) VALUES (?, ?, ?, ?)`,
      )
      .run(deviceId, publicKey, wrappedPrivate, cert);
  }

  device(): { deviceId: string; publicKey: Uint8Array; wrappedPrivate: Uint8Array; cert: Uint8Array } | undefined {
    const row = this.db.prepare('SELECT device_id, signature_pubkey, signature_privkey, device_cert FROM device').get();
    if (!row) return undefined;
    return {
      deviceId: String(row.device_id),
      publicKey: bytes(row.signature_pubkey),
      wrappedPrivate: bytes(row.signature_privkey),
      cert: bytes(row.device_cert),
    };
  }

  saveToken(hash: Uint8Array, label: string, topics: '*' | string[]): void {
    this.db
      .prepare(
        `INSERT INTO agent_tokens (token_hash, agent_label, topic_scope, created_at) VALUES (?, ?, ?, ?)`,
      )
      .run(hash, label, JSON.stringify(topics), new Date().toISOString());
  }

  token(hash: Uint8Array): TokenRow | undefined {
    const row = this.db
      .prepare('SELECT agent_label, topic_scope, created_at, revoked_at FROM agent_tokens WHERE token_hash = ?')
      .get(hash);
    if (!row || row.revoked_at !== null) return undefined;
    return {
      label: String(row.agent_label),
      topics: parseScope(String(row.topic_scope)),
      createdAt: String(row.created_at),
      revokedAt: null,
    };
  }

  tokens(): TokenRow[] {
    return this.db
      .prepare('SELECT agent_label, topic_scope, created_at, revoked_at FROM agent_tokens ORDER BY created_at')
      .all()
      .map((row) => ({
        label: String(row.agent_label),
        topics: parseScope(String(row.topic_scope)),
        createdAt: String(row.created_at),
        revokedAt: row.revoked_at === null ? null : String(row.revoked_at),
      }));
  }

  grantTopic(label: string, topicId: string): void {
    const row = this.db.prepare('SELECT topic_scope FROM agent_tokens WHERE agent_label = ?').get(label);
    if (!row) return;
    const scope = parseScope(String(row.topic_scope));
    if (scope === '*') return;
    if (scope.includes(topicId)) return;
    this.db
      .prepare('UPDATE agent_tokens SET topic_scope = ? WHERE agent_label = ?')
      .run(JSON.stringify([...scope, topicId]), label);
  }

  revokeToken(label: string): boolean {
    const result = this.db
      .prepare(`UPDATE agent_tokens SET revoked_at = ? WHERE agent_label = ? AND revoked_at IS NULL`)
      .run(new Date().toISOString(), label);
    return result.changes === 1;
  }

  /**
   * Persist the decrypted frame in the same transaction as the MLS write.
   * Returns a halt code when the shared state has diverged.
   */
  applyFrame(db: StoreDb, frame: PersistedFrame): string | undefined {
    const envelope = frame.envelope;
    if (!envelope) return undefined;
    const approvalOk = envelope.approval !== null && approvalVerifies(frame, envelope);
    db.prepare(
      `INSERT INTO envelopes (
         topic_id, seq, message_id, author_handle, author_agent, type, body, payload_json,
         approval_ok, applied, ts
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)`,
    ).run(
      frame.topicId,
      frame.seq,
      envelope.id,
      envelope.author.handle,
      envelope.author.agent ?? null,
      envelope.type,
      envelope.body ?? null,
      JSON.stringify(envelope.payload),
      approvalOk ? 1 : 0,
      envelope.ts,
    );
    if (envelope.type === 'state_snapshot') return applySnapshot(db, frame.topicId, frame.seq, envelope);
    if (envelope.type === 'state_patch') return applyStatePatch(db, frame.topicId, frame.seq, envelope);
    return undefined;
  }

  state(topicId: string): TopicStateRow | undefined {
    const row = this.db
      .prepare('SELECT version, doc_hash, doc_json, updated_seq FROM topic_state WHERE topic_id = ?')
      .get(topicId);
    if (!row) return undefined;
    return {
      version: Number(row.version),
      hash: bytes(row.doc_hash),
      doc: JSON.parse(String(row.doc_json)),
      updatedSeq: Number(row.updated_seq),
    };
  }

  envelopes(topicId: string, afterSeq: number, limit: number): EnvelopeRow[] {
    return this.db
      .prepare(
        `SELECT seq, message_id, author_handle, author_agent, type, body, payload_json, approval_ok, applied, ts
           FROM envelopes WHERE topic_id = ? AND seq > ? ORDER BY seq LIMIT ?`,
      )
      .all(topicId, afterSeq, limit)
      .map(envelopeRow);
  }

  cursor(label: string, topicId: string): number {
    const row = this.db
      .prepare('SELECT last_read_seq FROM read_cursors WHERE agent_label = ? AND topic_id = ?')
      .get(label, topicId);
    return row ? Number(row.last_read_seq) : 0;
  }

  advanceCursor(label: string, topicId: string, seq: number): void {
    this.db
      .prepare(
        `INSERT INTO read_cursors (agent_label, topic_id, last_read_seq) VALUES (?, ?, ?)
         ON CONFLICT (agent_label, topic_id) DO UPDATE SET last_read_seq = MAX(last_read_seq, excluded.last_read_seq)`,
      )
      .run(label, topicId, seq);
  }

  unread(label: string, topicId: string): number {
    const row = this.db
      .prepare(
        `SELECT count(*) AS n FROM envelopes e
           LEFT JOIN read_cursors c ON c.agent_label = ? AND c.topic_id = e.topic_id
          WHERE e.topic_id = ? AND e.seq > COALESCE(c.last_read_seq, 0)
            AND e.type IN ('update', 'question', 'request', 'answer', 'system', 'state_patch')`,
      )
      .get(label, topicId);
    return Number(row?.n ?? 0);
  }

  latestActivity(topicId: string): string | undefined {
    const row = this.db.prepare('SELECT ts FROM envelopes WHERE topic_id = ? ORDER BY seq DESC LIMIT 1').get(topicId);
    return row ? String(row.ts) : undefined;
  }

  saveApproval(row: {
    approvalId: string;
    topicId: string;
    kind: string;
    requestedBy: string;
    summary: string;
    request: unknown;
  }): void {
    this.db
      .prepare(
        `INSERT INTO approvals (
           approval_id, topic_id, kind, status, requested_by, summary, request_json, created_at
         ) VALUES (?, ?, ?, 'pending', ?, ?, ?, ?)`,
      )
      .run(row.approvalId, row.topicId, row.kind, row.requestedBy, row.summary, JSON.stringify(row.request), new Date().toISOString());
  }

  approval(id: string): ApprovalRow | undefined {
    const row = this.db.prepare('SELECT * FROM approvals WHERE approval_id = ?').get(id);
    return row ? approvalRow(row) : undefined;
  }

  approvals(topicIds: '*' | string[], status: string): ApprovalRow[] {
    const rows = this.db.prepare('SELECT * FROM approvals ORDER BY created_at').all();
    return rows.map(approvalRow).filter((row) => {
      if (status !== 'all' && row.status !== status) return false;
      if (topicIds === '*') return true;
      return topicIds.includes(row.topicId);
    });
  }

  decideApproval(id: string, status: 'approved' | 'rejected' | 'done' | 'expired'): void {
    this.db
      .prepare(`UPDATE approvals SET status = ?, decided_at = ? WHERE approval_id = ?`)
      .run(status, new Date().toISOString(), id);
  }

  seeMember(topicId: string, handle: string, role: string, when: string): void {
    const existing = this.db
      .prepare('SELECT joined_at, removed_at FROM member_seen WHERE topic_id = ? AND handle = ?')
      .get(topicId, handle);
    if (!existing) {
      this.db
        .prepare(
          `INSERT INTO member_seen (topic_id, handle, role, joined_at) VALUES (?, ?, ?, ?)`,
        )
        .run(topicId, handle, role, when);
      return;
    }
    this.db
      .prepare(`UPDATE member_seen SET role = ?, removed_at = NULL WHERE topic_id = ? AND handle = ?`)
      .run(role, topicId, handle);
  }

  markRemoved(topicId: string, handles: string[], when: string): void {
    for (const handle of handles) {
      this.db
        .prepare(
          `UPDATE member_seen SET removed_at = COALESCE(removed_at, ?) WHERE topic_id = ? AND handle = ?`,
        )
        .run(when, topicId, handle);
    }
  }

  members(topicId: string): Array<{ handle: string; role: string; joinedAt: string; removedAt: string | null }> {
    return this.db
      .prepare('SELECT handle, role, joined_at, removed_at FROM member_seen WHERE topic_id = ? ORDER BY joined_at')
      .all(topicId)
      .map((row) => ({
        handle: String(row.handle),
        role: String(row.role),
        joinedAt: String(row.joined_at),
        removedAt: row.removed_at === null ? null : String(row.removed_at),
      }));
  }

  verified(handle: string): boolean {
    const row = this.db.prepare('SELECT verified_at FROM contacts WHERE handle = ?').get(handle);
    return row !== undefined && row.verified_at !== null;
  }
}

function applySnapshot(db: StoreDb, topicId: string, seq: number, envelope: Envelope): string | undefined {
  const payload = envelope.payload;
  const doc = payload.doc;
  const version = payload.version;
  const claimed = typeof payload.hash === 'string' ? parseHashLabel(payload.hash) : undefined;
  if (typeof version !== 'number' || !Number.isInteger(version) || claimed === undefined) return 'state_diverged';
  const actual = hashBytes(doc);
  if (!bytesEqual(actual, claimed)) return 'state_diverged';
  const current = readState(db, topicId);
  if (current && current.version === version && bytesEqual(current.hash, actual)) return undefined;
  if (current && current.version === version && !bytesEqual(current.hash, actual)) return 'state_diverged';
  if (current && version < current.version) return undefined;
  writeState(db, topicId, version, actual, doc, seq);
  return undefined;
}

function applyStatePatch(db: StoreDb, topicId: string, seq: number, envelope: Envelope): string | undefined {
  const payload = envelope.payload;
  const baseVersion = payload.base_version;
  const baseHash = typeof payload.base_hash === 'string' ? parseHashLabel(payload.base_hash) : undefined;
  const patch = payload.patch;
  if (typeof baseVersion !== 'number' || baseHash === undefined || !Array.isArray(patch)) {
    markApplied(db, topicId, seq, false);
    return undefined;
  }
  const current = readState(db, topicId);
  if (!current || current.version !== baseVersion) {
    markApplied(db, topicId, seq, false);
    return undefined;
  }
  if (!bytesEqual(current.hash, baseHash)) return 'state_diverged';
  const applied = applyPatch(current.doc, patch as PatchOp[]);
  if (!applied.ok) {
    markApplied(db, topicId, seq, false);
    return undefined;
  }
  writeState(db, topicId, current.version + 1, hashBytes(applied.doc), applied.doc, seq);
  markApplied(db, topicId, seq, true);
  return undefined;
}

function approvalVerifies(frame: PersistedFrame, envelope: Envelope): boolean {
  if (!envelope.approval) return false;
  // The sender credential carries the identity key. A bad endorsement is not a
  // halt: MLS already authenticated the member, and receivers show approval "none".
  const sig = Buffer.from(envelope.approval.sig, 'base64');
  if (sig.length !== 64) return false;
  const key = frame.sender.credential.identityKey;
  const signature = new Uint8Array(sig);
  if (envelope.type === 'request') return verifyRequest(frame.topicId, envelope, key, signature);
  if (envelope.type === 'state_patch') return verifyState(frame.topicId, envelope, key, signature);
  return false;
}

function readState(db: StoreDb, topicId: string): TopicStateRow | undefined {
  const row = db.prepare('SELECT version, doc_hash, doc_json, updated_seq FROM topic_state WHERE topic_id = ?').get(topicId);
  if (!row) return undefined;
  return {
    version: Number(row.version),
    hash: bytes(row.doc_hash),
    doc: JSON.parse(String(row.doc_json)),
    updatedSeq: Number(row.updated_seq),
  };
}

function writeState(db: StoreDb, topicId: string, version: number, hash: Uint8Array, doc: unknown, seq: number): void {
  db.prepare(
    `INSERT INTO topic_state (topic_id, version, doc_hash, doc_json, updated_seq) VALUES (?, ?, ?, ?, ?)
     ON CONFLICT (topic_id) DO UPDATE SET
       version = excluded.version, doc_hash = excluded.doc_hash,
       doc_json = excluded.doc_json, updated_seq = excluded.updated_seq`,
  ).run(topicId, version, hash, JSON.stringify(doc), seq);
}

function markApplied(db: StoreDb, topicId: string, seq: number, applied: boolean): void {
  db.prepare('UPDATE envelopes SET applied = ? WHERE topic_id = ? AND seq = ?').run(applied ? 1 : 0, topicId, seq);
}

function envelopeRow(row: Record<string, unknown>): EnvelopeRow {
  return {
    seq: Number(row.seq),
    messageId: String(row.message_id),
    authorHandle: String(row.author_handle),
    authorAgent: row.author_agent === null ? null : String(row.author_agent),
    type: String(row.type),
    body: row.body === null ? null : String(row.body),
    payload: JSON.parse(String(row.payload_json)),
    approvalOk: Number(row.approval_ok) === 1,
    applied: row.applied === null ? null : Number(row.applied) === 1,
    ts: String(row.ts),
  };
}

function approvalRow(row: Record<string, unknown>): ApprovalRow {
  return {
    approvalId: String(row.approval_id),
    topicId: String(row.topic_id),
    kind: String(row.kind),
    status: String(row.status),
    requestedBy: String(row.requested_by),
    summary: String(row.summary),
    request: JSON.parse(String(row.request_json)),
    createdAt: String(row.created_at),
    decidedAt: row.decided_at === null ? null : String(row.decided_at),
  };
}

function parseScope(value: string): '*' | string[] {
  const parsed = JSON.parse(value) as unknown;
  if (parsed === '*') return '*';
  if (Array.isArray(parsed) && parsed.every((item) => typeof item === 'string')) return parsed;
  return [];
}

function bytes(value: unknown): Uint8Array {
  if (value instanceof Uint8Array) return new Uint8Array(value);
  throw new Error('expected a blob');
}
