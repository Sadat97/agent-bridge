import { DatabaseSync } from 'node:sqlite';
import { mkdtempSync, readFileSync, unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { PersistedFrame } from '@agent-bridge/mls';
import { hashBytes, hashLabel } from '../src/json.ts';
import { AesGcmSealer, randomStorageKey } from '../src/seal.ts';
import { LocalStore, scrubPlaintext } from '../src/local.ts';

const MARKER = 'secret-body-plaintext-9f3c2a';
const PAYLOAD = 'hidden-payload-zz-9f3c2a';

describe('envelope plaintext at rest', () => {
  it('seals body and payload with row associated data', () => {
    const { path, local } = openSealed();
    local.applyFrame(local.db, frame('topic-1', 1, MARKER));
    local.applyFrame(local.db, frame('topic-1', 2, 'other body'));
    const read = local.envelopes('topic-1', 0, 10);
    expect(read.map((row) => row.body)).toEqual([MARKER, 'other body']);
    expect(read[0]?.payload).toEqual({ note: PAYLOAD });

    const stored = local.db.prepare('SELECT body, payload_json, body_sealed, payload_sealed FROM envelopes WHERE seq = 1').get() as {
      body: string | null;
      payload_json: string;
      body_sealed: Uint8Array;
      payload_sealed: Uint8Array;
    };
    expect(stored.body).toBeNull();
    expect(stored.payload_json).toBe('');
    expect(Buffer.from(stored.body_sealed).includes(Buffer.from(MARKER))).toBe(false);
    expect(Buffer.from(stored.payload_sealed).includes(Buffer.from(PAYLOAD))).toBe(false);

    local.db
      .prepare('UPDATE envelopes SET payload_sealed = ? WHERE topic_id = ? AND seq = 2')
      .run(stored.payload_sealed, 'topic-1');
    expect(() => local.envelopes('topic-1', 1, 1)).toThrow(/could not be opened/);

    local.db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
    const disk = readFileSync(path);
    expect(disk.includes(Buffer.from(MARKER))).toBe(false);
    expect(disk.includes(Buffer.from(PAYLOAD))).toBe(false);
    local.close();
  });

  it('migrates envelope and topic-state plaintext, and a delete leaves none of it on disk', () => {
    const dir = mkdtempSync(join(tmpdir(), 'agb-migrate-'));
    const path = join(dir, 'store.sqlite');
    const stateDoc = { note: PAYLOAD, title: 'shared-state-plaintext-9f3c2a' };
    const db = new DatabaseSync(path);
    db.exec('PRAGMA journal_mode = WAL');
    db.exec(`CREATE TABLE envelopes (
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
    )`);
    db.exec(`CREATE TABLE topic_state (
      topic_id TEXT PRIMARY KEY,
      version INTEGER NOT NULL,
      doc_hash BLOB NOT NULL,
      doc_json TEXT NOT NULL,
      updated_seq INTEGER NOT NULL
    )`);
    db.prepare(
      `INSERT INTO envelopes (
         topic_id, seq, message_id, author_handle, type, body, payload_json, approval_ok, ts
       ) VALUES ('topic-1', 1, 'msg_old', 'ada', 'update', ?, ?, 0, '2026-11-01T00:00:00.000Z')`,
    ).run(MARKER, JSON.stringify({ note: PAYLOAD }));
    db.prepare(
      `INSERT INTO topic_state (topic_id, version, doc_hash, doc_json, updated_seq) VALUES ('topic-1', 0, ?, ?, 1)`,
    ).run(hashBytes(stateDoc), JSON.stringify(stateDoc));
    db.exec(`CREATE TABLE approvals (
      approval_id TEXT PRIMARY KEY,
      topic_id TEXT NOT NULL,
      kind TEXT NOT NULL,
      status TEXT NOT NULL,
      requested_by TEXT NOT NULL,
      summary TEXT NOT NULL,
      request_json TEXT NOT NULL,
      created_at TEXT NOT NULL
    )`);
    db.prepare(
      `INSERT INTO approvals (
         approval_id, topic_id, kind, status, requested_by, summary, request_json, created_at
       ) VALUES ('apr_old', 'topic-1', 'request', 'pending', 'ada/cli', ?, ?, '2026-11-01T00:00:00.000Z')`,
    ).run('approval-summary-plaintext-9f3c2a', JSON.stringify({ body: 'approval-request-plaintext-9f3c2a' }));
    db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
    db.close();

    const sealer = new AesGcmSealer(randomStorageKey());
    scrubPlaintext(path, sealer);
    expect(storeBytes(path).includes(Buffer.from(MARKER))).toBe(false);
    expect(storeBytes(path).includes(Buffer.from(PAYLOAD))).toBe(false);
    expect(storeBytes(path).includes(Buffer.from('shared-state-plaintext-9f3c2a'))).toBe(false);
    expect(storeBytes(path).includes(Buffer.from('approval-summary-plaintext-9f3c2a'))).toBe(false);
    expect(storeBytes(path).includes(Buffer.from('approval-request-plaintext-9f3c2a'))).toBe(false);

    const local = new LocalStore(path, { sealer });
    expect(local.envelopes('topic-1', 0, 10)[0]).toMatchObject({ body: MARKER, payload: { note: PAYLOAD } });
    expect(local.state('topic-1')?.doc).toEqual(stateDoc);
    expect(local.approval('apr_old')).toMatchObject({
      summary: 'approval-summary-plaintext-9f3c2a',
      request: { body: 'approval-request-plaintext-9f3c2a' },
    });
    const stored = local.db.prepare('SELECT body, payload_json, doc_json, doc_sealed FROM envelopes e JOIN topic_state s USING (topic_id)').get() as {
      body: string | null;
      payload_json: string;
      doc_json: string;
      doc_sealed: Uint8Array | null;
    };
    expect(stored.body).toBeNull();
    expect(stored.payload_json).toBe('');
    expect(stored.doc_json).toBe('');
    expect(stored.doc_sealed).toBeInstanceOf(Uint8Array);
    local.db.exec('PRAGMA secure_delete = ON');
    local.db.prepare('DELETE FROM envelopes').run();
    local.db.prepare('DELETE FROM topic_state').run();
    local.db.prepare('DELETE FROM approvals').run();
    local.scrubDisk();
    local.close();
    for (const suffix of ['-wal', '-shm', '-journal']) {
      try {
        unlinkSync(path + suffix);
      } catch {
        // Sidecar already gone.
      }
    }
    const afterDelete = storeBytes(path);
    expect(afterDelete.includes(Buffer.from(MARKER))).toBe(false);
    expect(afterDelete.includes(Buffer.from(PAYLOAD))).toBe(false);
    expect(afterDelete.includes(Buffer.from('shared-state-plaintext-9f3c2a'))).toBe(false);
    expect(afterDelete.includes(Buffer.from('approval-summary-plaintext-9f3c2a'))).toBe(false);
    expect(afterDelete.includes(Buffer.from('approval-request-plaintext-9f3c2a'))).toBe(false);
  });

  it('keeps JSON Patch compare-and-swap working when the document is sealed', () => {
    const { path, local } = openSealed();
    const doc = { trains: [] as unknown[], secret: 'shared-state-plaintext-9f3c2a' };
    local.applyFrame(local.db, snapshot('topic-1', 1, doc));
    const patched = local.applyFrame(
      local.db,
      patchFrame('topic-1', 2, doc, [{ op: 'add', path: '/platform', value: '9' }]),
    );
    expect(patched).toBeUndefined();
    const state = local.state('topic-1');
    expect(state?.version).toBe(1);
    expect(state?.doc).toEqual({ trains: [], secret: 'shared-state-plaintext-9f3c2a', platform: '9' });
    expect(Buffer.from(state!.hash)).toEqual(Buffer.from(hashBytes(state!.doc)));
    local.scrubDisk();
    local.close();
    expect(storeBytes(path).includes(Buffer.from('shared-state-plaintext-9f3c2a'))).toBe(false);
  });
});

function openSealed(): { path: string; local: LocalStore } {
  const dir = mkdtempSync(join(tmpdir(), 'agb-seal-env-'));
  const path = join(dir, 'store.sqlite');
  const local = new LocalStore(path, { sealer: new AesGcmSealer(randomStorageKey()) });
  return { path, local };
}

function frame(topicId: string, seq: number, body: string): PersistedFrame {
  return {
    topicId,
    seq,
    kind: 'application',
    authorMatches: true,
    envelope: {
      v: 1,
      id: `msg_${seq}`,
      type: 'update',
      ts: '2026-11-18T00:00:00.000Z',
      author: { handle: 'ada' },
      reply_to: null,
      body,
      payload: { note: PAYLOAD },
      approval: null,
    },
    sender: {
      leafIndex: 0,
      signatureKey: new Uint8Array(32),
      credential: {
        handle: 'ada',
        identityKey: new Uint8Array(32),
        deviceId: '00000000-0000-4000-8000-000000000001',
        deviceCert: new Uint8Array(),
      },
    },
  };
}

function tryRead(path: string): Buffer {
  try {
    return readFileSync(path);
  } catch {
    return Buffer.alloc(0);
  }
}

function storeBytes(path: string): Buffer {
  return Buffer.concat([path, path + '-wal', path + '-shm', path + '-journal'].map((file) => tryRead(file)));
}

function snapshot(topicId: string, seq: number, doc: unknown): PersistedFrame {
  const base = frame(topicId, seq, 'snapshot');
  base.envelope = {
    ...base.envelope!,
    type: 'state_snapshot',
    body: undefined,
    payload: { version: 0, hash: hashLabel(hashBytes(doc)), doc, reason: 'join' },
  };
  return base;
}

function patchFrame(topicId: string, seq: number, doc: unknown, patch: unknown[]): PersistedFrame {
  const base = frame(topicId, seq, 'patch');
  base.envelope = {
    ...base.envelope!,
    type: 'state_patch',
    body: undefined,
    payload: { base_version: 0, base_hash: hashLabel(hashBytes(doc)), patch, summary: 'add platform' },
  };
  return base;
}
