import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { generateEd25519KeyPair } from '@agent-bridge/protocol';
import { ORIGIN, startRelay } from '../../relay/test/helpers.ts';
import type { TestRelay } from '../../relay/test/helpers.ts';
import { Bridge, fingerprint, initBridge, openBridge } from '../src/index.ts';
import type { AgentCaller } from '../src/index.ts';
import { HUMAN_READ_LABEL } from '../src/group-view.ts';

const PASSPHRASE = 'test-passphrase-1';
const cli: AgentCaller = { label: 'cli', topics: '*' };

describe('group view routes', () => {
  let relay: TestRelay;
  let alice: Bridge;
  let bob: Bridge;
  let topicId = '';

  beforeAll(async () => {
    relay = await startRelay();
    const aliceHome = mkdtempSync(join(tmpdir(), 'agb-group-alice-'));
    const bobHome = mkdtempSync(join(tmpdir(), 'agb-group-bob-'));
    await initBridge({ home: aliceHome, handle: 'alice', relayOrigin: ORIGIN, relayUrl: relay.baseUrl, passphrase: PASSPHRASE });
    await initBridge({ home: bobHome, handle: 'bob', relayOrigin: ORIGIN, relayUrl: relay.baseUrl, passphrase: PASSPHRASE });
    alice = await openBridge({ home: aliceHome, serve: { host: '127.0.0.1', port: 0, approvalPort: 0 } });
    bob = await openBridge({ home: bobHome, serve: { host: '127.0.0.1', port: 0, approvalPort: 0 } });
    const created = await alice.createTopic(cli, {
      slug: 'austria',
      title: 'Austria trip',
      initial: { dates: '12–18 Feb', budget: '€900 each', travel: 'Train' },
    });
    topicId = created.topic_id;
    const invite = await alice.inviteMember(cli, topicId, 'bob');
    expect((await decide(alice.approvalPort, invite.approval_id!, 'approve', PASSPHRASE)).status).toBe(200);
    const joining = await waitFor(async () => {
      await bob.syncAll();
      const listed = await bob.listApprovals(cli, { status: 'pending' });
      return listed.items.find((item) => item.kind === 'join' && item.topic_id === topicId);
    });
    expect((await decide(bob.approvalPort, String(joining.approval_id), 'approve', PASSPHRASE)).status).toBe(200);
    await alice.syncAll();
    await bob.syncAll();
    await alice.postMessage(cli, { topicId, type: 'update', body: 'Both weeks work.' });
    await bob.postMessage(cli, { topicId, type: 'update', body: 'Hotel is still open.' });
    await alice.syncAll();
  }, 120_000);

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

  it('lists groups and renders a timeline without protocol noise', async () => {
    await alice.createTopic(cli, { slug: 'quiet', title: 'Quiet notes' });
    const agentCursor = alice.local.cursor('cli', topicId);
    const list = await fetch(`http://127.0.0.1:${alice.approvalPort}/groups`);
    expect(list.status).toBe(200);
    expect(list.headers.get('content-security-policy')).toContain("default-src 'none'");
    const listHtml = await list.text();
    expect(listHtml).toContain('Austria trip');
    expect(listHtml).toContain('Quiet notes');
    expect(listHtml).toContain("Bob&#39;s agent:");
    expect(listHtml).toContain('Hotel is still open.');
    expect(listHtml).toContain('class="badge"');
    expect(listHtml).not.toMatch(/passphrase/i);
    expect(listHtml).not.toContain('type="password"');
    expect(listHtml).not.toContain('sha256:');
    expect(listHtml).not.toContain('<script');
    expect(listHtml.replaceAll('xmlns="http://www.w3.org/2000/svg"', '')).not.toMatch(/https?:\/\//);

    const needs = await fetch(`http://127.0.0.1:${alice.approvalPort}/groups?filter=needs`);
    const needsHtml = await needs.text();
    expect(needsHtml).toContain('Nothing needs you.');
    expect(needsHtml).not.toContain('Austria trip');

    const topic = await fetch(`http://127.0.0.1:${alice.approvalPort}/groups/${topicId}`);
    expect(topic.status).toBe(200);
    const html = await topic.text();
    expect(html).toContain('class="msg mine"');
    expect(html).toContain('Both weeks work.');
    expect(html).toContain('>Bob <span class="tag">agent</span>');
    expect(html).toContain('<b>Trip</b>');
    expect(html).toContain('12–18 Feb');
    expect(html).toContain('€900 each');
    expect(html).toContain('class="fn">Travel</div>');
    expect(html).toContain('class="day"');
    expect(html).not.toContain('sha256:');
    expect(html).not.toMatch(/\bepoch\b/i);
    expect(html).not.toContain('post_message');
    expect(html).not.toContain('/_meta');
    expect(html).not.toMatch(/passphrase/i);
    expect(html).not.toContain('type="password"');
    expect(html).not.toContain('Write a message');
    expect(html).not.toContain(alice.fingerprint());
    expect(alice.local.cursor('cli', topicId)).toBe(agentCursor);
    expect(alice.local.cursor(HUMAN_READ_LABEL, topicId)).toBeGreaterThan(0);

    const read = await fetch(`http://127.0.0.1:${alice.approvalPort}/groups`);
    const readHtml = await read.text();
    const austria = readHtml.slice(readHtml.indexOf('Austria trip'), readHtml.indexOf('Austria trip') + 800);
    expect(austria).not.toContain('class="badge"');

    const token = (await import('node:fs')).readFileSync(alice.paths.cliToken, 'utf8').trim();
    const rejected = await fetch(`http://127.0.0.1:${alice.approvalPort}/groups`, {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(rejected.status).toBe(401);
  });

  it('wires Yes, No, and Edit to the approval actions and sends nothing without the passphrase', async () => {
    const spend = await alice.postMessage(cli, {
      topicId,
      type: 'request',
      body: 'Book the spa.',
      payload: { kind: 'spend', amount: 40 },
    });
    expect(spend.status).toBe('pending_approval');
    const page = await fetch(`http://127.0.0.1:${alice.approvalPort}/groups/${topicId}`);
    const html = await page.text();
    expect(html).toContain('Your agent wants to send this');
    expect(html).toContain('Book the spa.');
    expect(html).toContain('This spends 40.');
    expect(html).toContain(`/groups/${topicId}/approvals/${spend.approval_id}`);
    expect(html).not.toMatch(/passphrase/i);
    const { cookie, token } = csrfFrom(page, html);

    const forged = await fetch(`http://127.0.0.1:${alice.approvalPort}/groups/${topicId}/approvals/${spend.approval_id}`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', origin: 'http://evil.example' },
      body: new URLSearchParams({ csrf: token, decision: 'approve', passphrase: PASSPHRASE }),
    });
    expect(forged.status).toBe(403);

    const missing = await fetch(`http://127.0.0.1:${alice.approvalPort}/groups/${topicId}/approvals/${spend.approval_id}`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', cookie },
      body: new URLSearchParams({ csrf: 'nope', decision: 'approve' }),
    });
    expect(missing.status).toBe(403);
    expect(requestBody(alice, spend.approval_id!)).toBe('Book the spa.');

    const staged = await fetch(`http://127.0.0.1:${alice.approvalPort}/groups/${topicId}/approvals/${spend.approval_id}`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', cookie },
      body: new URLSearchParams({ csrf: token, decision: 'edit', body: 'Ask about the spa.' }),
    });
    expect(staged.status).toBe(200);
    const stagedHtml = await staged.text();
    expect(stagedHtml).toContain('Ask about the spa.');
    expect(stagedHtml).toMatch(/passphrase/i);
    expect(requestBody(alice, spend.approval_id!)).toBe('Book the spa.');
    await bob.syncAll();
    expect(bodies(await bob.readMessages(cli, { topicId, sinceSeq: 0 }))).not.toContain('Ask about the spa.');

    const confirmPage = csrfFrom(staged, stagedHtml);
    const confirmed = await fetch(`http://127.0.0.1:${alice.approvalPort}/approvals/${spend.approval_id}`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: confirmPage.cookie },
      body: new URLSearchParams({
        csrf: confirmPage.token,
        decision: 'approve',
        passphrase: PASSPHRASE,
        body: 'Ask about the spa.',
      }),
    });
    expect(confirmed.status).toBe(200);
    expect(await confirmed.text()).toContain('Approved');
    await bob.syncAll();
    const sent = bodies(await bob.readMessages(cli, { topicId, sinceSeq: 0 }));
    expect(sent).toContain('Ask about the spa.');
    expect(sent).not.toContain('Book the spa.');

    const external = await alice.postMessage(cli, {
      topicId,
      type: 'request',
      body: 'Email the hotel.',
      payload: { kind: 'external_message', to: 'hotel@example.com' },
    });
    const denyPage = await fetch(`http://127.0.0.1:${alice.approvalPort}/groups/${topicId}`);
    const denyHtml = await denyPage.text();
    expect(denyHtml).toContain('Email the hotel.');
    expect(denyHtml).toContain('This contacts someone outside the group: hotel@example.com.');
    const denyCsrf = csrfFrom(denyPage, denyHtml);
    const wrong = await fetch(`http://127.0.0.1:${alice.approvalPort}/groups/${topicId}/approvals/${external.approval_id}`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: denyCsrf.cookie },
      body: new URLSearchParams({ csrf: denyCsrf.token, decision: 'deny', passphrase: 'nope' }),
    });
    expect(wrong.status).toBe(401);
    expect(alice.local.approval(external.approval_id!)?.status).toBe('pending');
    const denied = await fetch(`http://127.0.0.1:${alice.approvalPort}/groups/${topicId}/approvals/${external.approval_id}`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: denyCsrf.cookie },
      body: new URLSearchParams({ csrf: denyCsrf.token, decision: 'deny', passphrase: PASSPHRASE }),
    });
    expect(denied.status).toBe(200);
    expect(await denied.text()).toContain('Denied');
    await bob.syncAll();
    expect(bodies(await bob.readMessages(cli, { topicId, sinceSeq: 0 }))).not.toContain('Email the hotel.');

    const direct = await alice.postMessage(cli, {
      topicId,
      type: 'request',
      body: 'Hold the train.',
      payload: { kind: 'spend', amount: 12 },
    });
    const directPage = await fetch(`http://127.0.0.1:${alice.approvalPort}/groups/${topicId}`);
    const directHtml = await directPage.text();
    const directCsrf = csrfFrom(directPage, directHtml);
    const approved = await fetch(`http://127.0.0.1:${alice.approvalPort}/groups/${topicId}/approvals/${direct.approval_id}`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: directCsrf.cookie },
      body: new URLSearchParams({
        csrf: directCsrf.token,
        decision: 'edit',
        body: 'Hold the later train.',
        passphrase: PASSPHRASE,
      }),
    });
    expect(approved.status).toBe(200);
    await bob.syncAll();
    const after = bodies(await bob.readMessages(cli, { topicId, sinceSeq: 0 }));
    expect(after).toContain('Hold the later train.');
    expect(after).not.toContain('Hold the train.');
  });

  it('links a key change to the existing verify form', async () => {
    const pinned = alice.mls.pins.get('bob')!;
    const rotated = generateEd25519KeyPair();
    await relay.pool.query('UPDATE accounts SET identity_pubkey = $1 WHERE handle = $2', [Buffer.from(rotated.publicKey), 'bob']);
    await alice.syncAll();
    const page = await fetch(`http://127.0.0.1:${alice.approvalPort}/groups/${topicId}`);
    const html = await page.text();
    expect(html).toContain("Bob&#39;s agent changed devices — check it&#39;s really them.");
    expect(html).toContain('href="/contacts/bob/verify"');
    expect(html).not.toContain(fingerprint(pinned));
    expect(html).not.toContain(fingerprint(rotated.publicKey));
    const check = await fetch(`http://127.0.0.1:${alice.approvalPort}/contacts/bob/verify`);
    expect(check.status).toBe(200);
    const verify = await check.text();
    expect(verify).toContain(fingerprint(pinned));
    expect(verify).toMatch(/passphrase/i);
    expect(verify).toContain('name="handle" value="bob"');
  });
});

function requestBody(bridge: Bridge, approvalId: string): string {
  const row = bridge.local.approval(approvalId);
  const request = row?.request as { body?: string } | undefined;
  return request?.body ?? '';
}

function bodies(page: { messages: Array<Record<string, unknown>> }): string[] {
  return page.messages.map((message) => String(message.body ?? ''));
}

async function decide(port: number, id: string, decision: 'approve' | 'deny', passphrase: string): Promise<Response> {
  const page = await fetch(`http://127.0.0.1:${port}/approvals/${id}`);
  const html = await page.text();
  const { cookie, token } = csrfFrom(page, html);
  return fetch(`http://127.0.0.1:${port}/approvals/${id}`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie },
    body: new URLSearchParams({ csrf: token, passphrase, decision }),
  });
}

function csrfFrom(res: Response, html: string): { cookie: string; token: string } {
  const token = /name="csrf" value="([^"]+)"/.exec(html)?.[1];
  if (!token) throw new Error('page did not include a csrf token');
  const set = res.headers.getSetCookie().find((line) => line.startsWith('agb_csrf='));
  if (!set) throw new Error('page did not set a csrf cookie');
  return { cookie: set.split(';')[0] ?? '', token };
}

async function waitFor<T>(fn: () => Promise<T | undefined>, attempts = 20): Promise<T> {
  for (let i = 0; i < attempts; i++) {
    const value = await fn();
    if (value) return value;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error('timed out waiting for the other bridge');
}
