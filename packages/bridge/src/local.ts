// Bridge rows that sit beside the MLS store in the same SQLite file.
// Envelope body and payload are sealed with the storage key before they reach
// disk. The shared-state document is not. Secrets that the MLS store already
// seals are not written here.

import { DatabaseSync } from 'node:sqlite';
import { existsSync, unlinkSync } from 'node:fs';
import { bytesEqual, fromUtf8, utf8 } from '@agent-bridge/protocol';
import type { Envelope, PersistedFrame, SecretSealer, StoreDb } from '@agent-bridge/mls';
import { BridgeError } from './errors.ts';
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

export interface ContactRecord {
  handle: string;
  identityKey: Uint8Array;
  verifiedAt: string | null;
  pendingKey: Uint8Array | null;
  pendingAt: string | null;
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
  doc_json TEXT NOT NULL DEFAULT '',
  doc_sealed BLOB,
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
  payload_json TEXT NOT NULL DEFAULT '',
  approval_ok INTEGER NOT NULL,
  applied INTEGER,
  ts TEXT NOT NULL,
  body_sealed BLOB,
  payload_sealed BLOB,
  PRIMARY KEY (topic_id, seq)
);
CREATE TABLE IF NOT EXISTS commit_clock (
  topic_id TEXT PRIMARY KEY,
  last_commit_at INTEGER NOT NULL
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
  readonly #sealer: SecretSealer | undefined;

  constructor(path: string, options?: { sealer?: SecretSealer }) {
    this.#sealer = options?.sealer;
    this.db = new DatabaseSync(path);
    this.db.exec('PRAGMA secure_delete = ON');
    this.db.exec('PRAGMA busy_timeout = 1000');
    this.db.exec(SCHEMA);
    this.#migrate();
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
    const sealed = this.#sealEnvelope(frame.topicId, frame.seq, envelope);
    db.prepare(
      `INSERT INTO envelopes (
         topic_id, seq, message_id, author_handle, author_agent, type, body, payload_json,
         approval_ok, applied, ts, body_sealed, payload_sealed
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?)`,
    ).run(
      frame.topicId,
      frame.seq,
      envelope.id,
      envelope.author.handle,
      envelope.author.agent ?? null,
      envelope.type,
      sealed.body,
      sealed.payloadJson,
      approvalOk ? 1 : 0,
      envelope.ts,
      sealed.bodySealed,
      sealed.payloadSealed,
    );
    if (envelope.type === 'state_snapshot') return applySnapshot(db, frame.topicId, frame.seq, envelope, this.#sealer);
    if (envelope.type === 'state_patch') return applyStatePatch(db, frame.topicId, frame.seq, envelope, this.#sealer);
    return undefined;
  }

  state(topicId: string): TopicStateRow | undefined {
    const row = this.db
      .prepare('SELECT version, doc_hash, doc_json, doc_sealed, updated_seq FROM topic_state WHERE topic_id = ?')
      .get(topicId);
    if (!row) return undefined;
    const version = Number(row.version);
    return {
      version,
      hash: bytes(row.doc_hash),
      doc: this.#readDoc(row, topicId, version),
      updatedSeq: Number(row.updated_seq),
    };
  }

  envelopes(topicId: string, afterSeq: number, limit: number): EnvelopeRow[] {
    return this.db
      .prepare(
        `SELECT topic_id, seq, message_id, author_handle, author_agent, type, body, payload_json,
                approval_ok, applied, ts, body_sealed, payload_sealed
           FROM envelopes WHERE topic_id = ? AND seq > ? ORDER BY seq LIMIT ?`,
      )
      .all(topicId, afterSeq, limit)
      .map((row) => this.#envelopeRow(row));
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

  updateRequest(id: string, request: unknown): void {
    this.db.prepare('UPDATE approvals SET request_json = ? WHERE approval_id = ?').run(JSON.stringify(request), id);
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
    const row = this.contact(handle);
    return row !== undefined && row.verifiedAt !== null && row.pendingKey === null;
  }

  keyChanged(handle: string): boolean {
    return this.contact(handle)?.pendingKey != null;
  }

  contact(handle: string): ContactRecord | undefined {
    const row = this.db
      .prepare(
        `SELECT handle, identity_pubkey, verified_at, pending_pubkey, pending_at
           FROM contacts WHERE handle = ?`,
      )
      .get(handle);
    return row ? contactRecord(row) : undefined;
  }

  contacts(): ContactRecord[] {
    return this.db
      .prepare(
        `SELECT handle, identity_pubkey, verified_at, pending_pubkey, pending_at
           FROM contacts ORDER BY handle`,
      )
      .all()
      .map(contactRecord);
  }

  /** Remember a relay key that is not the pin. The pin itself is not updated. */
  noteKeyChange(handle: string, pending: Uint8Array): void {
    const current = this.contact(handle);
    if (!current) return;
    if (current.pendingKey && bytesEqual(current.pendingKey, pending)) return;
    this.db
      .prepare('UPDATE contacts SET pending_pubkey = ?, pending_at = ? WHERE handle = ?')
      .run(pending, new Date().toISOString(), handle);
  }

  clearPending(handle: string): void {
    this.db.prepare('UPDATE contacts SET pending_pubkey = NULL, pending_at = NULL WHERE handle = ?').run(handle);
  }

  markVerified(handle: string): void {
    const result = this.db
      .prepare('UPDATE contacts SET verified_at = ? WHERE handle = ?')
      .run(new Date().toISOString(), handle);
    if (result.changes !== 1) throw new BridgeError('not_found', 'no such contact', 404);
  }

  noteCommit(topicId: string, at: number): void {
    this.db
      .prepare(
        `INSERT INTO commit_clock (topic_id, last_commit_at) VALUES (?, ?)
         ON CONFLICT (topic_id) DO UPDATE SET last_commit_at = excluded.last_commit_at`,
      )
      .run(topicId, at);
  }

  lastCommitAt(topicId: string): number | undefined {
    const row = this.db.prepare('SELECT last_commit_at FROM commit_clock WHERE topic_id = ?').get(topicId);
    if (!row) return undefined;
    return Number(row.last_commit_at);
  }

  #migrate(): void {
    const envelopes = columnSet(this.db, 'envelopes');
    if (envelopes.size > 0 && !envelopes.has('body_sealed')) {
      this.db.exec('ALTER TABLE envelopes ADD COLUMN body_sealed BLOB');
      this.db.exec('ALTER TABLE envelopes ADD COLUMN payload_sealed BLOB');
    }
    const contacts = columnSet(this.db, 'contacts');
    if (contacts.size > 0 && !contacts.has('verified_at')) {
      this.db.exec('ALTER TABLE contacts ADD COLUMN verified_at TEXT');
    }
    if (contacts.size > 0 && !contacts.has('pending_pubkey')) {
      this.db.exec('ALTER TABLE contacts ADD COLUMN pending_pubkey BLOB');
      this.db.exec('ALTER TABLE contacts ADD COLUMN pending_at TEXT');
    }
    const stateCols = columnSet(this.db, 'topic_state');
    if (stateCols.size > 0 && !stateCols.has('doc_sealed')) {
      this.db.exec('ALTER TABLE topic_state ADD COLUMN doc_sealed BLOB');
    }
    if (this.#sealer) this.#migratePlaintext();
  }

  /**
   * Rewrite the file so freed pages cannot keep old plaintext, then drop WAL
   * and rollback-journal sidecars. The caller must be the only connection.
   */
  scrubDisk(): void {
    this.db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
    this.db.exec('VACUUM');
    this.db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
  }

  /** Seal rows written before plaintext was wrapped. Plaintext columns are cleared. */
  #migratePlaintext(): void {
    const rows = this.db
      .prepare('SELECT topic_id, seq, body, payload_json, body_sealed, payload_sealed FROM envelopes')
      .all();
    const update = this.db.prepare(
      `UPDATE envelopes SET body = NULL, payload_json = '', body_sealed = ?, payload_sealed = ?
        WHERE topic_id = ? AND seq = ?`,
    );
    const stateRows = this.db
      .prepare('SELECT topic_id, version, doc_json, doc_sealed FROM topic_state')
      .all();
    const updateState = this.db.prepare(
      'UPDATE topic_state SET doc_json = \'\', doc_sealed = ? WHERE topic_id = ? AND version = ?',
    );
    let migrated = 0;
    this.db.exec('BEGIN IMMEDIATE');
    try {
      for (const row of rows) {
        if (row.body_sealed != null || row.payload_sealed != null) continue;
        const topicId = String(row.topic_id);
        const seq = Number(row.seq);
        const body = row.body === null || row.body === undefined ? null : String(row.body);
        const payload = row.payload_json === null || row.payload_json === undefined ? '{}' : String(row.payload_json);
        if (body === null && payload === '') continue;
        update.run(
          body === null ? null : this.#sealText(body, bodyAad(topicId, seq)),
          this.#sealText(payload === '' ? '{}' : payload, payloadAad(topicId, seq)),
          topicId,
          seq,
        );
        migrated += 1;
      }
      for (const row of stateRows) {
        if (row.doc_sealed != null) continue;
        const json = row.doc_json === null || row.doc_json === undefined ? '' : String(row.doc_json);
        if (json === '') continue;
        const topicId = String(row.topic_id);
        const version = Number(row.version);
        updateState.run(this.#sealText(json, stateAad(topicId, version)), topicId, version);
        migrated += 1;
      }
      this.db.exec('COMMIT');
    } catch (err) {
      this.db.exec('ROLLBACK');
      throw err;
    }
    // Free pages and the WAL keep the pre-image until the file is rebuilt.
    // This connection is the only one open while that happens (see scrubPlaintext).
    if (migrated > 0) this.scrubDisk();
  }

  #readDoc(row: Record<string, unknown>, topicId: string, version: number): unknown {
    if (row.doc_sealed != null) return JSON.parse(this.#openText(bytes(row.doc_sealed), stateAad(topicId, version)));
    if (typeof row.doc_json === 'string' && row.doc_json.length > 0) return JSON.parse(row.doc_json);
    return {};
  }

  #sealEnvelope(
    topicId: string,
    seq: number,
    envelope: Envelope,
  ): { body: string | null; payloadJson: string; bodySealed: Uint8Array | null; payloadSealed: Uint8Array | null } {
    const payload = JSON.stringify(envelope.payload);
    if (!this.#sealer) {
      return { body: envelope.body ?? null, payloadJson: payload, bodySealed: null, payloadSealed: null };
    }
    return {
      body: null,
      payloadJson: '',
      bodySealed: envelope.body === undefined ? null : this.#sealText(envelope.body, bodyAad(topicId, seq)),
      payloadSealed: this.#sealText(payload, payloadAad(topicId, seq)),
    };
  }

  #sealText(plain: string, aad: string): Uint8Array {
    if (!this.#sealer) throw new BridgeError('mls_error', 'storage key is missing', 500);
    return this.#sealer.seal(utf8(plain), utf8(aad));
  }

  #openText(sealed: Uint8Array, aad: string): string {
    if (!this.#sealer) throw new BridgeError('mls_error', 'stored message could not be opened', 500);
    try {
      return fromUtf8(this.#sealer.open(sealed, utf8(aad)));
    } catch (err) {
      if (err instanceof BridgeError) throw err;
      throw new BridgeError('mls_error', 'stored message could not be opened', 500);
    }
  }

  #envelopeRow(row: Record<string, unknown>): EnvelopeRow {
    const topicId = String(row.topic_id);
    const seq = Number(row.seq);
    return {
      seq,
      messageId: String(row.message_id),
      authorHandle: String(row.author_handle),
      authorAgent: row.author_agent === null ? null : String(row.author_agent),
      type: String(row.type),
      body: this.#readBody(row, topicId, seq),
      payload: this.#readPayload(row, topicId, seq),
      approvalOk: Number(row.approval_ok) === 1,
      applied: row.applied === null ? null : Number(row.applied) === 1,
      ts: String(row.ts),
    };
  }

  #readBody(row: Record<string, unknown>, topicId: string, seq: number): string | null {
    if (row.body_sealed != null) return this.#openText(bytes(row.body_sealed), bodyAad(topicId, seq));
    if (row.body === null || row.body === undefined) return null;
    return String(row.body);
  }

  #readPayload(row: Record<string, unknown>, topicId: string, seq: number): unknown {
    if (row.payload_sealed != null) {
      return JSON.parse(this.#openText(bytes(row.payload_sealed), payloadAad(topicId, seq)));
    }
    if (typeof row.payload_json === 'string' && row.payload_json.length > 0) return JSON.parse(row.payload_json);
    return {};
  }
}

function bodyAad(topicId: string, seq: number): string {
  return `envelope-body:${topicId}:${seq}`;
}

function payloadAad(topicId: string, seq: number): string {
  return `envelope-payload:${topicId}:${seq}`;
}

function columnSet(db: DatabaseSync, table: string): Set<string> {
  return new Set(
    db
      .prepare(`PRAGMA table_info(${table})`)
      .all()
      .map((row) => String(row.name)),
  );
}

function contactRecord(row: Record<string, unknown>): ContactRecord {
  return {
    handle: String(row.handle),
    identityKey: bytes(row.identity_pubkey),
    verifiedAt: row.verified_at === null || row.verified_at === undefined ? null : String(row.verified_at),
    pendingKey: row.pending_pubkey === null || row.pending_pubkey === undefined ? null : bytes(row.pending_pubkey),
    pendingAt: row.pending_at === null || row.pending_at === undefined ? null : String(row.pending_at),
  };
}

/** Read contacts without opening the bridge. The daemon's writes are already committed. */
export function readContacts(path: string): ContactRecord[] {
  const db = new DatabaseSync(path, { readOnly: true });
  try {
    db.exec('PRAGMA busy_timeout = 1000');
    const names = columnSet(db, 'contacts');
    if (!names.has('handle')) return [];
    const verified = names.has('verified_at') ? 'verified_at' : 'NULL AS verified_at';
    const pendingKey = names.has('pending_pubkey') ? 'pending_pubkey' : 'NULL AS pending_pubkey';
    const pendingAt = names.has('pending_at') ? 'pending_at' : 'NULL AS pending_at';
    return db
      .prepare(
        `SELECT handle, identity_pubkey, ${verified}, ${pendingKey}, ${pendingAt} FROM contacts ORDER BY handle`,
      )
      .all()
      .map(contactRecord);
  } finally {
    db.close();
  }
}

function applySnapshot(
  db: StoreDb,
  topicId: string,
  seq: number,
  envelope: Envelope,
  sealer: SecretSealer | undefined,
): string | undefined {
  const payload = envelope.payload;
  const doc = payload.doc;
  const version = payload.version;
  const claimed = typeof payload.hash === 'string' ? parseHashLabel(payload.hash) : undefined;
  if (typeof version !== 'number' || !Number.isInteger(version) || claimed === undefined) return 'state_diverged';
  const actual = hashBytes(doc);
  if (!bytesEqual(actual, claimed)) return 'state_diverged';
  const current = readState(db, topicId, sealer);
  if (current && current.version === version && bytesEqual(current.hash, actual)) return undefined;
  if (current && current.version === version && !bytesEqual(current.hash, actual)) return 'state_diverged';
  if (current && version < current.version) return undefined;
  writeState(db, topicId, version, actual, doc, seq, sealer);
  return undefined;
}

function applyStatePatch(
  db: StoreDb,
  topicId: string,
  seq: number,
  envelope: Envelope,
  sealer: SecretSealer | undefined,
): string | undefined {
  const payload = envelope.payload;
  const baseVersion = payload.base_version;
  const baseHash = typeof payload.base_hash === 'string' ? parseHashLabel(payload.base_hash) : undefined;
  const patch = payload.patch;
  if (typeof baseVersion !== 'number' || baseHash === undefined || !Array.isArray(patch)) {
    markApplied(db, topicId, seq, false);
    return undefined;
  }
  const current = readState(db, topicId, sealer);
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
  writeState(db, topicId, current.version + 1, hashBytes(applied.doc), applied.doc, seq, sealer);
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

function readState(db: StoreDb, topicId: string, sealer: SecretSealer | undefined): TopicStateRow | undefined {
  const row = db
    .prepare('SELECT version, doc_hash, doc_json, doc_sealed, updated_seq FROM topic_state WHERE topic_id = ?')
    .get(topicId);
  if (!row) return undefined;
  const version = Number(row.version);
  return {
    version,
    hash: bytes(row.doc_hash),
    doc: readDoc(row, topicId, version, sealer),
    updatedSeq: Number(row.updated_seq),
  };
}

function writeState(
  db: StoreDb,
  topicId: string,
  version: number,
  hash: Uint8Array,
  doc: unknown,
  seq: number,
  sealer: SecretSealer | undefined,
): void {
  const json = JSON.stringify(doc);
  const sealed = sealer ? sealer.seal(utf8(json), utf8(stateAad(topicId, version))) : null;
  db.prepare(
    `INSERT INTO topic_state (topic_id, version, doc_hash, doc_json, doc_sealed, updated_seq) VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT (topic_id) DO UPDATE SET
       version = excluded.version, doc_hash = excluded.doc_hash,
       doc_json = excluded.doc_json, doc_sealed = excluded.doc_sealed, updated_seq = excluded.updated_seq`,
  ).run(topicId, version, hash, sealed ? '' : json, sealed, seq);
}

function readDoc(row: Record<string, unknown>, topicId: string, version: number, sealer: SecretSealer | undefined): unknown {
  if (row.doc_sealed != null) {
    if (!sealer) throw new BridgeError('mls_error', 'stored state could not be opened', 500);
    try {
      return JSON.parse(fromUtf8(sealer.open(bytes(row.doc_sealed), utf8(stateAad(topicId, version)))));
    } catch (err) {
      if (err instanceof BridgeError) throw err;
      throw new BridgeError('mls_error', 'stored state could not be opened', 500);
    }
  }
  if (typeof row.doc_json === 'string' && row.doc_json.length > 0) return JSON.parse(row.doc_json);
  return {};
}

export function stateAad(topicId: string, version: number): string {
  return `topic-state:${topicId}:${version}`;
}

/** Seal leftover plaintext and rebuild the file before any other connection opens. */
export function scrubPlaintext(path: string, sealer: SecretSealer): void {
  if (!existsSync(path)) return;
  const local = new LocalStore(path, { sealer });
  try {
    // Migration vacuums when it rewrites rows. Vacuum again so a file that
    // only needed secure_delete still drops free pages and the WAL.
    local.scrubDisk();
  } finally {
    local.close();
  }
  for (const suffix of ['-wal', '-shm', '-journal']) {
    try {
      unlinkSync(path + suffix);
    } catch {
      // Already removed by the checkpoint.
    }
  }
}

function markApplied(db: StoreDb, topicId: string, seq: number, applied: boolean): void {
  db.prepare('UPDATE envelopes SET applied = ? WHERE topic_id = ? AND seq = ?').run(applied ? 1 : 0, topicId, seq);
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
