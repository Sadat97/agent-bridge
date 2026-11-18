import { DatabaseSync } from 'node:sqlite';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { PersistedFrame } from '@agent-bridge/mls';
import { AesGcmSealer, randomStorageKey } from '../src/seal.ts';
import { LocalStore } from '../src/local.ts';

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

  it('migrates plaintext rows already on disk', () => {
    const dir = mkdtempSync(join(tmpdir(), 'agb-migrate-'));
    const path = join(dir, 'store.sqlite');
    const db = new DatabaseSync(path);
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
    db.prepare(
      `INSERT INTO envelopes (
         topic_id, seq, message_id, author_handle, type, body, payload_json, approval_ok, ts
       ) VALUES ('topic-1', 1, 'msg_old', 'ada', 'update', ?, ?, 0, '2026-11-01T00:00:00.000Z')`,
    ).run(MARKER, JSON.stringify({ note: PAYLOAD }));
    db.close();

    const sealer = new AesGcmSealer(randomStorageKey());
    const local = new LocalStore(path, { sealer });
    expect(local.envelopes('topic-1', 0, 10)[0]).toMatchObject({ body: MARKER, payload: { note: PAYLOAD } });
    const stored = local.db.prepare('SELECT body, payload_json, body_sealed FROM envelopes').get() as {
      body: string | null;
      payload_json: string;
      body_sealed: Uint8Array | null;
    };
    expect(stored.body).toBeNull();
    expect(stored.payload_json).toBe('');
    expect(stored.body_sealed).toBeInstanceOf(Uint8Array);
    local.db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
    local.close();
    const disk = Buffer.concat([readFileSync(path), tryRead(path + '-wal')]);
    expect(disk.includes(Buffer.from(MARKER))).toBe(false);
    expect(disk.includes(Buffer.from(PAYLOAD))).toBe(false);
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
