// SQLite persistence for one bridge's MLS topics.
//
// Processing a message writes the new group state, the seq, the message record
// and any consumed approval ids in one transaction. MLS ratchets are not
// idempotent, so a crash leaves either the old state or the new one, never a
// mix, and never applies the same message twice. `crashBeforeCommit` is the
// test seam that throws after those writes are staged and before COMMIT.

import { DatabaseSync } from 'node:sqlite';
import type { SQLOutputValue } from 'node:sqlite';
import { bytesEqual } from '@agent-bridge/protocol';
import { MlsOperationError } from './errors.ts';

export type TopicStatus = 'active' | 'pending_join' | 'halted' | 'left';
export type TopicRole = 'owner' | 'member';

export interface TopicRow {
  topicId: string;
  status: TopicStatus;
  role: TopicRole;
  ourHandle: string;
  devicePublicKey: Uint8Array;
  ownerIdentityKey: Uint8Array;
  engineId: string;
  mlsState: Uint8Array;
  epoch: bigint;
  lastSeq: number;
  haltReason: string | null;
  haltSeq: number | null;
  /** Application generations burned by abort since peers last caught up. */
  applicationDiscards: number;
  /** Handshake generations burned by aborting a commit in this epoch. */
  handshakeDiscards: number;
}

export interface NewTopic {
  topicId: string;
  status: TopicStatus;
  role: TopicRole;
  ourHandle: string;
  devicePublicKey: Uint8Array;
  ownerIdentityKey: Uint8Array;
  engineId: string;
  mlsState: Uint8Array;
  epoch: bigint;
  lastSeq: number;
}

export interface StoredMessage {
  seq: number;
  signatureKey: Uint8Array;
  type: string;
  authorMatches: boolean;
}

export interface PendingRow {
  message: Uint8Array;
  welcome: Uint8Array | null;
  mlsState: Uint8Array;
  manifestJson: string;
}

export interface TopicWrite {
  mlsState: Uint8Array;
  epoch: bigint;
  lastSeq: number;
  status: TopicStatus;
  clearPending: boolean;
  /**
   * Keep `topics.mls_state` (the last confirmed state) and store `mlsState`
   * on the staged outbound row instead. Used when an application ratchet was
   * already consumed and a same-epoch message has to be merged on top of it.
   */
  preserveConfirmed?: boolean;
  message?: { signatureKey: Uint8Array; type: string; authorMatches: boolean };
  approvalIds?: string[];
  pins?: Array<{ handle: string; identityKey: Uint8Array }>;
  /** Unpublished application drafts peers still have to skip. */
  applicationDiscards?: number;
  /** Unpublished handshake drafts peers still have to skip. */
  handshakeDiscards?: number;
}

export interface IdentityPin {
  handle: string;
  identityKey: Uint8Array;
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS contacts (
  handle TEXT PRIMARY KEY,
  identity_pubkey BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS topics (
  topic_id TEXT PRIMARY KEY,
  status TEXT NOT NULL,
  role TEXT NOT NULL,
  our_handle TEXT NOT NULL,
  device_public_key BLOB NOT NULL,
  owner_identity_key BLOB NOT NULL,
  mls_engine TEXT NOT NULL,
  mls_state BLOB NOT NULL,
  epoch INTEGER NOT NULL,
  last_seq INTEGER NOT NULL,
  halt_reason TEXT,
  halt_seq INTEGER,
  app_discards INTEGER NOT NULL DEFAULT 0,
  hs_discards INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS messages (
  topic_id TEXT NOT NULL,
  seq INTEGER NOT NULL,
  sender_signature_key BLOB NOT NULL,
  type TEXT NOT NULL,
  author_matches INTEGER NOT NULL,
  PRIMARY KEY (topic_id, seq)
);
CREATE TABLE IF NOT EXISTS consumed_approvals (
  topic_id TEXT NOT NULL,
  approval_id TEXT NOT NULL,
  PRIMARY KEY (topic_id, approval_id)
);
CREATE TABLE IF NOT EXISTS pending_outbound (
  topic_id TEXT PRIMARY KEY,
  message BLOB NOT NULL,
  welcome BLOB,
  mls_state BLOB NOT NULL,
  manifest_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS key_packages (
  key_package_ref BLOB PRIMARY KEY,
  private_package BLOB NOT NULL,
  expires_at INTEGER NOT NULL
);
`;

export class MlsStore {
  /** When set, the next transaction throws after staging its writes and rolls back. */
  crashBeforeCommit = false;
  /** Live pin map. Updated only after a transaction commits. */
  readonly pins = new Map<string, Uint8Array>();
  readonly #db: DatabaseSync;

  constructor(path: string) {
    this.#db = new DatabaseSync(path);
    this.#db.prepare('PRAGMA journal_mode = WAL').get();
    this.#db.exec('PRAGMA synchronous = FULL');
    this.#db.exec(SCHEMA);
    this.#addColumn('topics', 'app_discards', 'INTEGER NOT NULL DEFAULT 0');
    this.#addColumn('topics', 'hs_discards', 'INTEGER NOT NULL DEFAULT 0');
    for (const row of this.#db.prepare('SELECT handle, identity_pubkey FROM contacts').all()) {
      this.pins.set(text(row.handle, 'handle'), blob(row.identity_pubkey, 'identity_pubkey'));
    }
  }

  close(): void {
    this.#db.close();
  }

  transaction(fn: () => void): void {
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      fn();
      if (this.crashBeforeCommit) throw new Error('crash before commit');
      this.#db.exec('COMMIT');
    } catch (err) {
      this.#db.exec('ROLLBACK');
      throw err;
    }
  }

  createTopic(topic: NewTopic, pins: IdentityPin[], dropKeyPackage?: Uint8Array): void {
    const remembered: IdentityPin[] = [];
    this.transaction(() => {
      this.#db
        .prepare(
          `INSERT INTO topics (
             topic_id, status, role, our_handle, device_public_key, owner_identity_key,
             mls_engine, mls_state, epoch, last_seq
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          topic.topicId,
          topic.status,
          topic.role,
          topic.ourHandle,
          topic.devicePublicKey,
          topic.ownerIdentityKey,
          topic.engineId,
          topic.mlsState,
          epochNumber(topic.epoch),
          topic.lastSeq,
        );
      for (const pin of pins) {
        if (this.#insertPin(pin)) remembered.push(pin);
      }
      if (dropKeyPackage) {
        this.#db.prepare('DELETE FROM key_packages WHERE key_package_ref = ?').run(dropKeyPackage);
      }
    });
    for (const pin of remembered) this.pins.set(pin.handle, pin.identityKey.slice());
  }

  topic(topicId: string): TopicRow | undefined {
    const row = this.#db.prepare('SELECT * FROM topics WHERE topic_id = ?').get(topicId);
    if (!row) return undefined;
    const status = text(row.status, 'status');
    const role = text(row.role, 'role');
    if (!isStatus(status) || !isRole(role)) throw new MlsOperationError('mls_error', 'stored topic status is invalid');
    return {
      topicId,
      status,
      role,
      ourHandle: text(row.our_handle, 'our_handle'),
      devicePublicKey: blob(row.device_public_key, 'device_public_key'),
      ownerIdentityKey: blob(row.owner_identity_key, 'owner_identity_key'),
      engineId: text(row.mls_engine, 'mls_engine'),
      mlsState: blob(row.mls_state, 'mls_state'),
      epoch: BigInt(integer(row.epoch, 'epoch')),
      lastSeq: integer(row.last_seq, 'last_seq'),
      haltReason: row.halt_reason === null ? null : text(row.halt_reason, 'halt_reason'),
      haltSeq: row.halt_seq === null ? null : integer(row.halt_seq, 'halt_seq'),
      applicationDiscards: integer(row.app_discards, 'app_discards'),
      handshakeDiscards: integer(row.hs_discards, 'hs_discards'),
    };
  }

  setStatus(topicId: string, from: TopicStatus, to: TopicStatus): void {
    this.transaction(() => {
      const result = this.#db
        .prepare('UPDATE topics SET status = ? WHERE topic_id = ? AND status = ?')
        .run(to, topicId, from);
      if (result.changes !== 1) throw new MlsOperationError('mls_error', `topic is not ${from}`);
    });
  }

  messages(topicId: string): StoredMessage[] {
    return this.#db
      .prepare('SELECT seq, sender_signature_key, type, author_matches FROM messages WHERE topic_id = ? ORDER BY seq')
      .all(topicId)
      .map((row) => ({
        seq: integer(row.seq, 'seq'),
        signatureKey: blob(row.sender_signature_key, 'sender_signature_key'),
        type: text(row.type, 'type'),
        authorMatches: integer(row.author_matches, 'author_matches') === 1,
      }));
  }

  approvalIds(topicId: string): string[] {
    return this.#db
      .prepare('SELECT approval_id FROM consumed_approvals WHERE topic_id = ?')
      .all(topicId)
      .map((row) => text(row.approval_id, 'approval_id'));
  }

  pending(topicId: string): PendingRow | undefined {
    const row = this.#db
      .prepare('SELECT message, welcome, mls_state, manifest_json FROM pending_outbound WHERE topic_id = ?')
      .get(topicId);
    if (!row) return undefined;
    return {
      message: blob(row.message, 'message'),
      welcome: row.welcome === null ? null : blob(row.welcome, 'welcome'),
      mlsState: blob(row.mls_state, 'mls_state'),
      manifestJson: text(row.manifest_json, 'manifest_json'),
    };
  }

  stagePending(topicId: string, row: PendingRow): void {
    this.transaction(() => {
      const existing = this.#db.prepare('SELECT 1 AS hit FROM pending_outbound WHERE topic_id = ?').get(topicId);
      if (existing) throw new MlsOperationError('outbound_pending', 'an outbound message is already staged');
      this.#db
        .prepare('INSERT INTO pending_outbound (topic_id, message, welcome, mls_state, manifest_json) VALUES (?, ?, ?, ?, ?)')
        .run(topicId, row.message, row.welcome, row.mlsState, row.manifestJson);
    });
  }

  /**
   * The staged ciphertext is being discarded, but the ratchet generation it
   * consumed stays consumed. The next encrypt continues from `mlsState`.
   */
  keepRatchet(
    topicId: string,
    mlsState: Uint8Array,
    epoch: bigint,
    discards: { application: number; handshake: number },
  ): void {
    this.transaction(() => {
      const result = this.#db
        .prepare('UPDATE topics SET mls_state = ?, epoch = ?, app_discards = ?, hs_discards = ? WHERE topic_id = ?')
        .run(mlsState, epochNumber(epoch), discards.application, discards.handshake, topicId);
      if (result.changes !== 1) throw new MlsOperationError('not_found', 'no such topic');
      this.#db.prepare('DELETE FROM pending_outbound WHERE topic_id = ?').run(topicId);
    });
  }

  clearPending(topicId: string): void {
    this.transaction(() => {
      this.#db.prepare('DELETE FROM pending_outbound WHERE topic_id = ?').run(topicId);
    });
  }

  /**
   * Advance a topic by one seq. The previous last_seq must be `write.lastSeq - 1`,
   * so a replay or a gap rolls the whole write back.
   */
  writeTopic(topicId: string, write: TopicWrite): IdentityPin[] {
    const remembered: IdentityPin[] = [];
    this.transaction(() => {
      const current = this.#db.prepare('SELECT last_seq FROM topics WHERE topic_id = ?').get(topicId);
      if (!current) throw new MlsOperationError('not_found', 'no such topic');
      const lastSeq = integer(current.last_seq, 'last_seq');
      if (write.lastSeq !== lastSeq + 1) {
        throw new MlsOperationError('seq_gap', `topic is at seq ${lastSeq}, cannot write ${write.lastSeq}`);
      }
      if (write.preserveConfirmed) {
        this.#db.prepare('UPDATE topics SET last_seq = ? WHERE topic_id = ?').run(write.lastSeq, topicId);
        const pending = this.#db
          .prepare('UPDATE pending_outbound SET mls_state = ? WHERE topic_id = ?')
          .run(write.mlsState, topicId);
        if (pending.changes !== 1) throw new MlsOperationError('mls_error', 'no staged outbound to merge into');
      } else {
        this.#db
          .prepare(
            `UPDATE topics
                SET mls_state = ?, epoch = ?, last_seq = ?, status = ?,
                    halt_reason = NULL, halt_seq = NULL,
                    app_discards = COALESCE(?, app_discards),
                    hs_discards = COALESCE(?, hs_discards)
              WHERE topic_id = ?`,
          )
          .run(
            write.mlsState,
            epochNumber(write.epoch),
            write.lastSeq,
            write.status,
            write.applicationDiscards ?? null,
            write.handshakeDiscards ?? null,
            topicId,
          );
      }
      if (write.message) {
        this.#db
          .prepare(
            'INSERT INTO messages (topic_id, seq, sender_signature_key, type, author_matches) VALUES (?, ?, ?, ?, ?)',
          )
          .run(topicId, write.lastSeq, write.message.signatureKey, write.message.type, write.message.authorMatches ? 1 : 0);
      }
      for (const approvalId of write.approvalIds ?? []) {
        this.#db
          .prepare('INSERT INTO consumed_approvals (topic_id, approval_id) VALUES (?, ?)')
          .run(topicId, approvalId);
      }
      for (const pin of write.pins ?? []) {
        if (this.#insertPin(pin)) remembered.push(pin);
      }
      if (write.clearPending) this.#db.prepare('DELETE FROM pending_outbound WHERE topic_id = ?').run(topicId);
    });
    for (const pin of remembered) this.pins.set(pin.handle, pin.identityKey.slice());
    return remembered;
  }

  /** Keep the pre-commit MLS state. Record the halt and drop any staged send. */
  halt(topicId: string, seq: number, reason: string): void {
    this.transaction(() => {
      const result = this.#db
        .prepare(
          `UPDATE topics SET status = 'halted', halt_reason = ?, halt_seq = ?
            WHERE topic_id = ? AND status != 'halted'`,
        )
        .run(reason, seq, topicId);
      if (result.changes !== 1) throw new MlsOperationError('topic_halted', 'topic is already halted');
      this.#db.prepare('DELETE FROM pending_outbound WHERE topic_id = ?').run(topicId);
    });
  }

  saveKeyPackage(ref: Uint8Array, privatePackage: Uint8Array, expiresAt: number): void {
    this.transaction(() => {
      this.#db
        .prepare(
          `INSERT INTO key_packages (key_package_ref, private_package, expires_at) VALUES (?, ?, ?)
           ON CONFLICT (key_package_ref) DO NOTHING`,
        )
        .run(ref, privatePackage, expiresAt);
    });
  }

  keyPackages(nowSeconds: number): Array<{ ref: Uint8Array; privatePackage: Uint8Array }> {
    return this.#db
      .prepare('SELECT key_package_ref, private_package FROM key_packages WHERE expires_at > ? ORDER BY expires_at')
      .all(nowSeconds)
      .map((row) => ({
        ref: blob(row.key_package_ref, 'key_package_ref'),
        privatePackage: blob(row.private_package, 'private_package'),
      }));
  }

  #addColumn(table: string, column: string, definition: string): void {
    const present = this.#db
      .prepare(`PRAGMA table_info(${table})`)
      .all()
      .some((row) => text(row.name, 'name') === column);
    if (!present) this.#db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  }

  /** Insert a pin or accept the same key. Throws, without writing, when the key differs. */
  #insertPin(pin: IdentityPin): boolean {
    const existing = this.#db.prepare('SELECT identity_pubkey FROM contacts WHERE handle = ?').get(pin.handle);
    if (existing) {
      if (!bytesEqual(blob(existing.identity_pubkey, 'identity_pubkey'), pin.identityKey)) {
        throw new MlsOperationError('pin_mismatch', `identity key for ${pin.handle} does not match the pinned key`);
      }
      return false;
    }
    this.#db.prepare('INSERT INTO contacts (handle, identity_pubkey) VALUES (?, ?)').run(pin.handle, pin.identityKey);
    return true;
  }
}

function epochNumber(epoch: bigint): number {
  if (epoch < 0n || epoch > BigInt(Number.MAX_SAFE_INTEGER)) throw new MlsOperationError('mls_error', 'epoch out of range');
  return Number(epoch);
}

function blob(value: SQLOutputValue | undefined, label: string): Uint8Array {
  if (value instanceof Uint8Array) return new Uint8Array(value);
  throw new MlsOperationError('mls_error', `${label} is not a blob`);
}

function text(value: SQLOutputValue | undefined, label: string): string {
  if (typeof value === 'string') return value;
  throw new MlsOperationError('mls_error', `${label} is not text`);
}

function integer(value: SQLOutputValue | undefined, label: string): number {
  if (typeof value === 'bigint') {
    if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw new MlsOperationError('mls_error', `${label} is out of range`);
    return Number(value);
  }
  if (typeof value === 'number' && Number.isSafeInteger(value)) return value;
  throw new MlsOperationError('mls_error', `${label} is not an integer`);
}

function isStatus(value: string): value is TopicStatus {
  return value === 'active' || value === 'pending_join' || value === 'halted' || value === 'left';
}

function isRole(value: string): value is TopicRole {
  return value === 'owner' || value === 'member';
}
