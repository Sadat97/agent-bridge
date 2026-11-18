import { DatabaseSync } from 'node:sqlite';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ORIGIN, startRelay } from '../../relay/test/helpers.ts';
import type { TestRelay } from '../../relay/test/helpers.ts';
import { UNPUBLISHED_GENERATION_SKIP } from '@agent-bridge/mls';
import { Bridge, initBridge, openBridge } from '../src/index.ts';
import type { AgentCaller } from '../src/index.ts';
import { bridgePaths } from '../src/bridge.ts';

const PASSPHRASE = 'test-passphrase-1';
const cli: AgentCaller = { label: 'cli', topics: '*' };

describe('two bridges on a local relay', () => {
  let relay: TestRelay;
  let alice: Bridge;
  let bob: Bridge;
  let topicId = '';

  beforeAll(async () => {
    relay = await startRelay();
    const aliceHome = mkdtempSync(join(tmpdir(), 'agb-alice-'));
    const bobHome = mkdtempSync(join(tmpdir(), 'agb-bob-'));
    await initBridge({ home: aliceHome, handle: 'alice', relayOrigin: ORIGIN, relayUrl: relay.baseUrl, passphrase: PASSPHRASE });
    await initBridge({ home: bobHome, handle: 'bob', relayOrigin: ORIGIN, relayUrl: relay.baseUrl, passphrase: PASSPHRASE });
    const aliceFile = readFileSync(bridgePaths(aliceHome).sqlite);
    expect(aliceFile.includes(Buffer.from(PASSPHRASE))).toBe(false);
    alice = await openBridge({ home: aliceHome, serve: { host: '127.0.0.1', port: 0, approvalPort: 0 } });
    bob = await openBridge({ home: bobHome });
  }, 60_000);

  afterAll(async () => {
    await Promise.race([
      (async () => {
        await alice?.close();
        await bob?.close();
      })(),
      new Promise((resolve) => setTimeout(resolve, 4000)),
    ]);
    if (relay) await Promise.race([relay.close(), new Promise((resolve) => setTimeout(resolve, 2000))]);
  }, 10_000);

  it('rejects a foreign origin, a missing token, and an agent token on the approval port', async () => {
    const base = `http://127.0.0.1:${alice.port}`;
    const origin = await fetch(`${base}/v1/topics`, { headers: { origin: 'http://evil.example' } });
    expect(origin.status).toBe(403);
    const missing = await fetch(`${base}/v1/topics`);
    expect(missing.status).toBe(401);
    const token = readFileSync(alice.paths.cliToken, 'utf8').trim();
    const ok = await fetch(`${base}/v1/whoami`, { headers: { authorization: `Bearer ${token}` } });
    expect(ok.status).toBe(200);
    expect(await ok.json()).toMatchObject({ handle: 'alice' });
    const human = await fetch(`http://127.0.0.1:${alice.approvalPort}/approvals/apr_x/approve`, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: JSON.stringify({ passphrase: PASSPHRASE }),
    });
    expect(human.status).toBe(401);
    const mcp = await fetch(`${base}/mcp`, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize' }),
    });
    const body = (await mcp.json()) as { result: { instructions: string; protocolVersion: string } };
    expect(body.result.instructions).toContain('list_topics');
    expect(body.result.protocolVersion).toBe('2025-11-25');
    const openTokens = await fetch(`http://127.0.0.1:${alice.approvalPort}/tokens`);
    expect(openTokens.status).toBe(401);
    const listed = await fetch(`http://127.0.0.1:${alice.approvalPort}/tokens/list`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ passphrase: PASSPHRASE }),
    });
    expect(listed.status).toBe(200);
    const tokens = (await listed.json()) as { tokens: Array<{ agent_label: string }> };
    expect(tokens.tokens.map((item) => item.agent_label)).toContain('cli');
  });

  it('adds the second person, posts, and keeps a spend request unsigned until the passphrase', async () => {
    const created = await alice.createTopic(cli, { slug: 'zurich', title: 'Zurich trip', initial: { trains: [] } });
    topicId = created.topic_id;
    expect(created.state_version).toBe(0);
    const invite = await alice.inviteMember(cli, topicId, 'bob');
    expect(invite.status).toBe('pending_approval');
    await alice.approve(invite.approval_id!, PASSPHRASE);

    const join = await waitFor(async () => {
      await bob.syncAll();
      const listed = await bob.listApprovals(cli, { status: 'pending' });
      return listed.items.find((item) => item.kind === 'join');
    });
    await bob.approve(String(join.approval_id), PASSPHRASE);
    await alice.syncAll();
    await bob.syncAll();

    const posted = await alice.postMessage(cli, { topicId, type: 'update', body: 'direct train on the 28th' });
    expect(posted.status).toBe('posted');
    await bob.syncAll();
    const read = await bob.readMessages(cli, { topicId });
    expect(read.messages).toContainEqual(expect.objectContaining({ body: 'direct train on the 28th', approval: 'none' }));

    const spend = await alice.postMessage(cli, {
      topicId,
      type: 'request',
      body: 'book the morning train',
      payload: { kind: 'spend', amount: 79 },
    });
    expect(spend.status).toBe('pending_approval');
    await bob.syncAll();
    expect((await bob.readMessages(cli, { topicId, sinceSeq: 0 })).messages.map((message) => message.body)).not.toContain(
      'book the morning train',
    );
    const approved = await alice.approve(spend.approval_id!, PASSPHRASE);
    expect(approved.status).toBe('approved');
    await bob.syncAll();
    const after = await bob.readMessages(cli, { topicId, sinceSeq: 0 });
    expect(after.messages).toContainEqual(expect.objectContaining({ body: 'book the morning train', approval: 'signed' }));
  });

  it('converges concurrent self-updates', async () => {
    await Promise.all([alice.selfUpdate(topicId), bob.selfUpdate(topicId)]);
    await alice.syncAll();
    await bob.syncAll();
    const left = await alice.postMessage(cli, { topicId, type: 'update', body: 'alice still here' });
    const right = await bob.postMessage(cli, { topicId, type: 'update', body: 'bob still here' });
    expect(left.status).toBe('posted');
    expect(right.status).toBe('posted');
    await alice.syncAll();
    await bob.syncAll();
    const chat = (bodies: unknown[]) => bodies.filter((body) => body !== 'state snapshot');
    const aliceBodies = (await alice.readMessages(cli, { topicId, sinceSeq: 0 })).messages.map((message) => message.body);
    const bobBodies = (await bob.readMessages(cli, { topicId, sinceSeq: 0 })).messages.map((message) => message.body);
    expect(chat(aliceBodies)).toEqual(chat(bobBodies));
    expect(aliceBodies).toEqual(expect.arrayContaining(['alice still here', 'bob still here']));
    expect((await alice.listTopics(cli, false)).topics.find((topic) => topic.topic_id === topicId)).toMatchObject({
      status: 'active',
    });
    expect((await bob.listTopics(cli, false)).topics.find((topic) => topic.topic_id === topicId)).toMatchObject({
      status: 'active',
    });
  });

  it('applies one of two concurrent patches and reports conflict for the other', async () => {
    const state = await alice.getState(cli, topicId);
    await bob.syncAll();
    const bobState = await bob.getState(cli, topicId);
    expect(bobState.version).toBe(state.version);
    const [fromAlice, fromBob] = await Promise.all([
      alice.proposeState(cli, {
        topicId,
        baseVersion: state.version,
        patch: [{ op: 'add', path: '/from_alice', value: 1 }],
        summary: 'alice field',
      }),
      bob.proposeState(cli, {
        topicId,
        baseVersion: bobState.version,
        patch: [{ op: 'add', path: '/from_bob', value: 2 }],
        summary: 'bob field',
      }),
    ]);
    expect([fromAlice.status, fromBob.status].sort()).toEqual(['applied', 'conflict']);
    await alice.syncAll();
    await bob.syncAll();
    const endAlice = await alice.getState(cli, topicId);
    const endBob = await bob.getState(cli, topicId);
    expect(endAlice.version).toBe(endBob.version);
    expect(endAlice.hash).toBe(endBob.hash);
    expect(endAlice.doc).toEqual(endBob.doc);
    const doc = endAlice.doc as Record<string, unknown>;
    const winners = ['from_alice', 'from_bob'].filter((key) => key in doc);
    expect(winners).toHaveLength(1);
    expect((await alice.readMessages(cli, { topicId, sinceSeq: 0, types: ['system'] })).messages.length).toBeGreaterThan(0);
  });

  it('retries an invite with no KeyPackage on sync, for 7 days, without a second approve', async () => {
    await relay.pool.query('DELETE FROM key_packages WHERE device_id = $1', [bob.config.deviceId]);
    const created = await alice.createTopic(cli, { slug: 'retry-kp', title: 'Retry' });
    const invite = await alice.inviteMember(cli, created.topic_id, 'bob');
    const decided = await alice.approve(invite.approval_id!, PASSPHRASE);
    expect(decided.status).toBe('pending');
    const pending = await alice.listApprovals(cli, { status: 'pending' });
    expect(pending.items.some((item) => item.approval_id === invite.approval_id)).toBe(true);
    const db = new DatabaseSync(alice.paths.sqlite, { readOnly: true });
    try {
      const row = db.prepare('SELECT summary, request_json FROM approvals WHERE approval_id = ?').get(invite.approval_id!) as
        | { summary: string; request_json: string }
        | undefined;
      expect(row?.summary).toBe('');
      expect(row?.request_json).toBe('');
    } finally {
      db.close();
    }
    const request = alice.local.approval(invite.approval_id!)?.request as { expiresAt?: number };
    expect(request.expiresAt).toBeTypeOf('number');
    expect(request.expiresAt! - Math.floor(Date.now() / 1000)).toBeGreaterThan(6 * 24 * 60 * 60);
    await bob.syncAll();
    await alice.syncAll();
    const join = await waitFor(async () => {
      await bob.syncAll();
      const listed = await bob.listApprovals(cli, { status: 'pending' });
      return listed.items.find((item) => item.kind === 'join' && item.topic_id === created.topic_id);
    });
    expect(join).toBeDefined();
    const still = await alice.listApprovals(cli, { status: 'pending' });
    expect(still.items.some((item) => item.approval_id === invite.approval_id)).toBe(false);
  });

  it('self-updates after the unpublished cap and the next post still decrypts', async () => {
    for (let i = 0; i < UNPUBLISHED_GENERATION_SKIP; i++) await alice.discardDraft(topicId);
    await expect(alice.discardDraft(topicId)).rejects.toMatchObject({ code: 'self_update_required', status: 409 });
    const seq = await alice.selfUpdate(topicId);
    expect(seq).toBeGreaterThan(0);
    await bob.syncAll();
    expect((await bob.listTopics(cli, false)).topics.find((topic) => topic.topic_id === topicId)).toMatchObject({
      status: 'active',
    });
    const token = readFileSync(alice.paths.cliToken, 'utf8').trim();
    const posted = await fetch(`http://127.0.0.1:${alice.port}/v1/topics/${topicId}/messages`, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: JSON.stringify({ type: 'update', body: 'after the cap' }),
    });
    const body = (await posted.json()) as { status?: string; error?: string };
    expect(posted.status).toBe(200);
    expect(body.status).toBe('posted');
    expect(body.error).toBeUndefined();
    await bob.syncAll();
    const read = await bob.readMessages(cli, { topicId, sinceSeq: 0 });
    expect(read.messages).toContainEqual(expect.objectContaining({ body: 'after the cap' }));
    expect((await alice.listTopics(cli, false)).topics.find((topic) => topic.topic_id === topicId)).toMatchObject({
      status: 'active',
    });
  });

  it('does not report another topic when sync is out of scope', async () => {
    const raw = alice.createToken('outsider', []);
    const res = await fetch(`http://127.0.0.1:${alice.port}/mcp`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${raw}`,
        'content-type': 'application/json',
        accept: 'application/json',
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 7,
        method: 'tools/call',
        params: { name: 'sync', arguments: { topic_id: topicId } },
      }),
    });
    const body = (await res.json()) as { result: { isError?: boolean; content?: Array<{ text: string }> } };
    expect(body.result.isError).toBe(true);
    const text = body.result.content?.[0]?.text ?? '';
    expect(text).toContain('out_of_scope');
    expect(text).not.toContain('new_messages');
  });

  it('removes a member who leaves', async () => {
    const seq = await bob.leaveTopic(topicId, PASSPHRASE);
    expect(seq).toBeGreaterThan(0);
    await waitFor(async () => {
      await alice.syncAll();
      await bob.syncAll();
      const members = await alice.listMembers(cli, topicId);
      const row = members.members.find((member) => member.handle === 'bob');
      return row?.removed_at ? row : undefined;
    });
    expect((await bob.listTopics(cli, false)).topics.find((topic) => topic.topic_id === topicId)).toBeUndefined();
    const raw = alice.createToken('reader', '*');
    const reader = alice.agentForToken(raw)!;
    const updatesOnly = await alice.readMessages(reader, { topicId, types: ['update'] });
    expect(updatesOnly.messages.every((message) => message.type === 'update')).toBe(true);
    const rest = await alice.readMessages(reader, { topicId });
    expect(rest.messages.some((message) => message.type === 'system' && String(message.body).includes('left'))).toBe(true);
  });

  it('hides a topic from an agent whose token does not include it', async () => {
    const token = alice.createToken('narrow', []);
    const agent = alice.agentForToken(token);
    expect(agent).toBeDefined();
    expect((await alice.listTopics(agent!, false)).topics).toEqual([]);
    await expect(alice.postMessage(agent!, { topicId, type: 'update', body: 'nope' })).rejects.toMatchObject({
      code: 'out_of_scope',
    });
  });
});

async function waitFor<T>(fn: () => Promise<T | undefined>, attempts = 20): Promise<T> {
  for (let i = 0; i < attempts; i++) {
    const value = await fn();
    if (value) return value;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error('timed out waiting for the other bridge');
}
