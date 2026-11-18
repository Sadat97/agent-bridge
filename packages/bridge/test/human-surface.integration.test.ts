import { spawn } from 'node:child_process';
import { DatabaseSync } from 'node:sqlite';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { generateEd25519KeyPair } from '@agent-bridge/protocol';
import { ORIGIN, startRelay } from '../../relay/test/helpers.ts';
import type { TestRelay } from '../../relay/test/helpers.ts';
import { Bridge, SELF_UPDATE_INTERVAL_MS, fingerprint, fingerprintQrPayload, initBridge, openBridge } from '../src/index.ts';
import type { AgentCaller } from '../src/index.ts';

const PASSPHRASE = 'test-passphrase-1';
const cli: AgentCaller = { label: 'cli', topics: '*' };
const MARKER = 'sealed-marker-9f3c2a';

describe('human surface', () => {
  let relay: TestRelay;
  let alice: Bridge;
  let bob: Bridge;
  let aliceHome = '';
  let topicId = '';

  beforeAll(async () => {
    relay = await startRelay();
    aliceHome = mkdtempSync(join(tmpdir(), 'agb-alice-'));
    const bobHome = mkdtempSync(join(tmpdir(), 'agb-bob-'));
    const carolHome = mkdtempSync(join(tmpdir(), 'agb-carol-'));
    await initBridge({ home: aliceHome, handle: 'alice', relayOrigin: ORIGIN, relayUrl: relay.baseUrl, passphrase: PASSPHRASE });
    await initBridge({ home: bobHome, handle: 'bob', relayOrigin: ORIGIN, relayUrl: relay.baseUrl, passphrase: PASSPHRASE });
    await initBridge({ home: carolHome, handle: 'carol', relayOrigin: ORIGIN, relayUrl: relay.baseUrl, passphrase: PASSPHRASE });
    alice = await openBridge({ home: aliceHome, serve: { host: '127.0.0.1', port: 0, approvalPort: 0 } });
    bob = await openBridge({ home: bobHome, serve: { host: '127.0.0.1', port: 0, approvalPort: 0 } });
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

  it('serves a loopback approval page and keeps tokens behind the passphrase', async () => {
    const port = alice.approvalPort;
    const page = await fetch(`http://127.0.0.1:${port}/`);
    expect(page.status).toBe(200);
    expect(page.headers.get('content-type')).toContain('text/html');
    expect(page.headers.get('content-security-policy')).toContain("default-src 'none'");
    const html = await page.text();
    expect(html).toContain(alice.fingerprint());
    expect(html).toContain('<svg');
    expect(html.replaceAll('xmlns="http://www.w3.org/2000/svg"', '')).not.toMatch(/<script|https?:\/\/|src=/);
    const { cookie, token } = csrfFrom(page, html);

    const forged = await fetch(`http://127.0.0.1:${port}/approvals/apr_missing`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', cookie, origin: 'http://evil.example' },
      body: new URLSearchParams({ csrf: token, passphrase: PASSPHRASE, decision: 'approve' }),
    });
    expect(forged.status).toBe(403);

    const noCsrf = await fetch(`http://127.0.0.1:${port}/approvals/apr_missing`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', cookie },
      body: new URLSearchParams({ csrf: 'not-the-token', passphrase: PASSPHRASE, decision: 'approve' }),
    });
    expect(noCsrf.status).toBe(403);

    const agent = readFileSync(alice.paths.cliToken, 'utf8').trim();
    const tools = await fetch(`http://127.0.0.1:${alice.port}/mcp`, {
      method: 'POST',
      headers: { authorization: `Bearer ${agent}`, 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' }),
    });
    const toolBody = (await tools.json()) as { result: { tools: Array<{ name: string; annotations?: { destructiveHint?: boolean } }> } };
    const names = toolBody.result.tools.map((tool) => tool.name);
    expect(names).toEqual([
      'list_topics',
      'create_topic',
      'list_members',
      'invite_member',
      'remove_member',
      'read_messages',
      'post_message',
      'get_state',
      'propose_state_change',
      'list_approvals',
      'sync',
    ]);
    expect(toolBody.result.tools.find((tool) => tool.name === 'remove_member')?.annotations?.destructiveHint).toBe(true);
    const rejected = await fetch(`http://127.0.0.1:${port}/`, { headers: { authorization: `Bearer ${agent}` } });
    expect(rejected.status).toBe(401);
    const openTokens = await fetch(`http://127.0.0.1:${port}/tokens`);
    expect(openTokens.status).toBe(401);
    const listed = await fetch(`http://127.0.0.1:${port}/tokens/list`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ passphrase: PASSPHRASE }),
    });
    expect(listed.status).toBe(200);
    const tokens = (await listed.json()) as { tokens: Array<{ agent_label: string }> };
    expect(tokens.tokens.map((item) => item.agent_label)).toContain('cli');

    const formTokens = await fetch(`http://127.0.0.1:${port}/tokens/list`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', cookie },
      body: new URLSearchParams({ csrf: token, passphrase: PASSPHRASE }),
    });
    expect(formTokens.status).toBe(200);
    const formHtml = await formTokens.text();
    expect(formHtml).toContain('cli');
    expect(formHtml).not.toContain(agent);
  });

  it('approves and denies held actions from the page, with the passphrase', async () => {
    const created = await alice.createTopic(cli, { slug: 'zurich', title: 'Zurich trip', initial: { trains: [] } });
    topicId = created.topic_id;
    const invite = await alice.inviteMember(cli, topicId, 'bob');
    const invitePage = await fetch(`http://127.0.0.1:${alice.approvalPort}/approvals/${invite.approval_id}`);
    const inviteHtml = await invitePage.text();
    expect(inviteHtml).toContain('unverified');
    expect(inviteHtml).toContain(fingerprint(alice.mls.pins.get('bob')!));
    expect(inviteHtml).toContain('<svg');
    const approved = await decide(alice.approvalPort, invite.approval_id!, 'approve', PASSPHRASE);
    expect(approved.status).toBe(200);
    expect(await approved.text()).toContain('Approved');

    const join = await waitFor(async () => {
      await bob.syncAll();
      const listed = await bob.listApprovals(cli, { status: 'pending' });
      return listed.items.find((item) => item.kind === 'join' && item.topic_id === topicId);
    });
    const joined = await decide(bob.approvalPort, String(join.approval_id), 'approve', PASSPHRASE);
    expect(joined.status).toBe(200);
    await alice.syncAll();
    await bob.syncAll();

    const spend = await alice.postMessage(cli, {
      topicId,
      type: 'request',
      body: 'book the morning train',
      payload: { kind: 'spend', amount: 79 },
    });
    expect(spend.status).toBe('pending_approval');
    const wrong = await decide(alice.approvalPort, spend.approval_id!, 'approve', 'nope');
    expect(wrong.status).toBe(401);
    const spent = await decide(alice.approvalPort, spend.approval_id!, 'approve', PASSPHRASE);
    expect(spent.status).toBe(200);
    await bob.syncAll();
    expect((await bob.readMessages(cli, { topicId, sinceSeq: 0 })).messages).toContainEqual(
      expect.objectContaining({ body: 'book the morning train', approval: 'signed' }),
    );

    const external = await alice.postMessage(cli, {
      topicId,
      type: 'request',
      body: 'email the hotel',
      payload: { kind: 'external_message', to: 'hotel@example.com' },
    });
    expect((await alice.listApprovals(cli, { status: 'pending' })).items).toContainEqual(
      expect.objectContaining({ approval_id: external.approval_id, hold: 'external_message' }),
    );
    const denied = await decide(alice.approvalPort, external.approval_id!, 'deny', PASSPHRASE);
    expect(denied.status).toBe(200);
    expect(await denied.text()).toContain('Denied');
    await bob.syncAll();
    expect((await bob.readMessages(cli, { topicId, sinceSeq: 0 })).messages.map((message) => message.body)).not.toContain(
      'email the hotel',
    );

    const state = await alice.getState(cli, topicId);
    const sensitive = await alice.proposeState(cli, {
      topicId,
      baseVersion: state.version,
      patch: [{ op: 'add', path: '/spend', value: { hotel: 40 } }],
      summary: 'hotel on the sensitive path',
    });
    expect(sensitive.status).toBe('pending_approval');
    const detail = await alice.approvalDetail(cli, sensitive.approval_id!);
    expect(detail.hold).toBe('sensitive_path');
    expect(detail.sensitive_paths).toEqual(['/spend']);
    await alice.reject(sensitive.approval_id!, PASSPHRASE);
  });

  it('pins on first sight, verifies from digits or a QR payload, and blocks a key change', async () => {
    const before = await alice.listMembers(cli, topicId);
    expect(before.members.find((member) => member.handle === 'bob')).toMatchObject({ verified: false, key_changed: false });
    const bobPrint = fingerprint(alice.mls.pins.get('bob')!);
    await alice.verifyContact('bob', bobPrint, PASSPHRASE);
    expect((await alice.listMembers(cli, topicId)).members.find((member) => member.handle === 'bob')).toMatchObject({
      verified: true,
      key_changed: false,
      fingerprint: bobPrint,
    });

    const invite = await alice.inviteMember(cli, topicId, 'carol');
    expect(alice.contact('carol')).toMatchObject({ verified: false, key_changed: false });
    const pinned = alice.mls.pins.get('carol')!;
    const rotated = generateEd25519KeyPair();
    await relay.pool.query('UPDATE accounts SET identity_pubkey = $1 WHERE handle = $2', [Buffer.from(rotated.publicKey), 'carol']);
    await alice.syncAll();
    expect(alice.contact('carol')).toMatchObject({
      key_changed: true,
      verified: false,
      pending_fingerprint: fingerprint(rotated.publicKey),
      fingerprint: fingerprint(pinned),
    });
    const home = await fetch(`http://127.0.0.1:${alice.approvalPort}/`);
    expect(await home.text()).toContain('Key changed for carol');
    await expect(alice.approve(invite.approval_id!, PASSPHRASE)).rejects.toMatchObject({ code: 'contact_key_changed' });
    await alice.verifyContact('carol', fingerprint(pinned), PASSPHRASE);
    expect(alice.contact('carol')?.key_changed).toBe(true);
    await expect(alice.approve(invite.approval_id!, PASSPHRASE)).rejects.toMatchObject({ code: 'contact_key_changed' });

    const page = await fetch(`http://127.0.0.1:${alice.approvalPort}/`);
    const html = await page.text();
    const { cookie, token } = csrfFrom(page, html);
    const verified = await fetch(`http://127.0.0.1:${alice.approvalPort}/contacts/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', cookie },
      body: new URLSearchParams({
        csrf: token,
        handle: 'carol',
        fingerprint: fingerprintQrPayload(rotated.publicKey),
        passphrase: PASSPHRASE,
      }),
    });
    expect(verified.status).toBe(200);
    expect(alice.contact('carol')).toMatchObject({ key_changed: false, verified: true, fingerprint: fingerprint(rotated.publicKey) });
    await expect(alice.approve(invite.approval_id!, PASSPHRASE)).rejects.toMatchObject({ code: 'mls_error' });
    expect((await alice.listTopics(cli, false)).topics.find((topic) => topic.topic_id === topicId)).toMatchObject({
      status: 'active',
    });

    const bobKey = alice.mls.pins.get('bob')!;
    const bobNext = generateEd25519KeyPair();
    await relay.pool.query('UPDATE accounts SET identity_pubkey = $1 WHERE handle = $2', [Buffer.from(bobNext.publicKey), 'bob']);
    await alice.syncAll();
    expect(() => alice.verifyContact('bob', fingerprintQrPayload(bobNext.publicKey), PASSPHRASE)).toThrow(
      /still a member under the pinned key/,
    );
    expect(alice.mls.pins.get('bob')).toEqual(bobKey);
    await relay.pool.query('UPDATE accounts SET identity_pubkey = $1 WHERE handle = $2', [Buffer.from(bobKey), 'bob']);
    await alice.syncAll();
    expect(alice.contact('bob')).toMatchObject({ key_changed: false, verified: true });

    const posted = await alice.postMessage(cli, { topicId, type: 'update', body: MARKER });
    expect(posted.status).toBe('posted');
    await bob.syncAll();
    expect((await bob.readMessages(cli, { topicId, sinceSeq: 0 })).messages).toContainEqual(
      expect.objectContaining({ body: MARKER }),
    );
    alice.local.db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
    const rows = alice.local.db.prepare('SELECT body, payload_json, body_sealed FROM envelopes').all() as Array<{
      body: string | null;
      payload_json: string;
      body_sealed: Uint8Array | null;
    }>;
    expect(rows.length).toBeGreaterThan(0);
    for (const row of rows) {
      expect(row.body).toBeNull();
      expect(row.payload_json).toBe('');
      expect(row.body_sealed === null || !Buffer.from(row.body_sealed).includes(Buffer.from(MARKER))).toBe(true);
    }
  });

  it('lists held actions from the CLI and refuses a passphrase without a TTY', async () => {
    const listed = await agb(['approvals', 'list', '--status', 'pending', '--json'], alice);
    expect(listed.code).toBe(0);
    const body = JSON.parse(listed.stdout) as { items: Array<{ kind: string; hold: string | null }> };
    expect(body.items.some((item) => item.kind === 'invite' || item.hold === 'spend' || item.hold === null || item.hold)).toBe(true);

    const printed = await agb(['fingerprint', '--json'], alice);
    expect(printed.code).toBe(0);
    expect(JSON.parse(printed.stdout)).toMatchObject({ handle: 'alice', qr_payload: fingerprintQrPayload(alice.credential.identityKey) });

    const text = await agb(['fingerprint'], alice);
    expect(text.code).toBe(0);
    expect(text.stdout).toContain(alice.fingerprint());
    expect(text.stdout).toMatch(/[▀▄█]/);

    const contacts = await agb(['contact', 'list', '--json'], alice);
    expect(contacts.code).toBe(0);
    const parsed = JSON.parse(contacts.stdout) as { contacts: Array<{ handle: string; key_changed: boolean }> };
    expect(parsed.contacts.map((contact) => contact.handle).sort()).toEqual(['bob', 'carol']);

    const shown = await agb(['contact', 'show', 'bob'], alice);
    expect(shown.code).toBe(0);
    expect(shown.stdout).toContain(fingerprint(alice.mls.pins.get('bob')!));
    expect(shown.stdout).toMatch(/[▀▄█]/);

    const noTty = await agb(['approvals', 'approve', 'apr_missing'], alice);
    expect(noTty.code).toBe(1);
    expect(noTty.stdout).toContain('TTY');

    const pty = await agbPty(['contact', 'verify', 'bob', fingerprint(alice.mls.pins.get('bob')!)], alice, PASSPHRASE);
    expect(pty.code).toBe(0);
    expect(pty.stdout).toContain('bob');
  }, 40_000);

  it('self-updates when the stored commit clock is 7 days old, including after a restart', async () => {
    alice.local.noteCommit(topicId, Date.now() - SELF_UPDATE_INTERVAL_MS - 1000);
    expect(await alice.runDueSelfUpdates()).toContain(topicId);
    expect(await alice.runDueSelfUpdates()).not.toContain(topicId);
    const quiet = alice.local.lastCommitAt(topicId)!;
    await bob.syncAll();
    const posted = await alice.postMessage(cli, { topicId, type: 'update', body: 'after the weekly update' });
    expect(posted.status).toBe('posted');

    await alice.close();
    const db = new DatabaseSync(join(aliceHome, 'store.sqlite'));
    db.exec('PRAGMA busy_timeout = 1000');
    db.prepare('UPDATE commit_clock SET last_commit_at = ? WHERE topic_id = ?').run(Date.now() - SELF_UPDATE_INTERVAL_MS - 1000, topicId);
    db.close();
    alice = await openBridge({ home: aliceHome, serve: { host: '127.0.0.1', port: 0, approvalPort: 0 } });
    const rotated = alice.local.lastCommitAt(topicId)!;
    expect(rotated).toBeGreaterThan(quiet);
    await alice.close();
    alice = await openBridge({ home: aliceHome, serve: { host: '127.0.0.1', port: 0, approvalPort: 0 } });
    expect(alice.local.lastCommitAt(topicId)).toBe(rotated);
    await bob.syncAll();
    expect((await bob.readMessages(cli, { topicId, sinceSeq: 0 })).messages).toContainEqual(
      expect.objectContaining({ body: 'after the weekly update' }),
    );
    expect((await alice.listTopics(cli, false)).topics.find((topic) => topic.topic_id === topicId)).toMatchObject({
      status: 'active',
    });
  });
});

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
  if (!token) throw new Error('approval page did not include a csrf token');
  const set = res.headers.getSetCookie().find((line) => line.startsWith('agb_csrf='));
  if (!set) throw new Error('approval page did not set a csrf cookie');
  return { cookie: set.split(';')[0] ?? '', token };
}

function agb(args: string[], bridge: Bridge): Promise<{ code: number; stdout: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [new URL('../src/cli.ts', import.meta.url).pathname, ...args, '--home', bridge.home, '--port', String(bridge.port), '--approval-port', String(bridge.approvalPort)], {
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    child.stdin.end();
    const out: Buffer[] = [];
    child.stdout.on('data', (chunk: Buffer) => out.push(chunk));
    child.stderr.on('data', () => undefined);
    child.on('error', reject);
    child.on('close', (code) => resolve({ code: code ?? 1, stdout: Buffer.concat(out).toString('utf8') }));
  });
}

function agbPty(args: string[], bridge: Bridge, passphrase: string): Promise<{ code: number; stdout: string }> {
  const script = `
import os, pty, select, sys
passphrase = os.environ.pop('AGB_TEST_PASSPHRASE')
argv = [sys.argv[1], *sys.argv[2:]]
env = os.environ.copy()
pid, fd = pty.fork()
if pid == 0:
    os.execve(argv[0], argv, env)
data = b''
sent = False
while True:
    ready, _, _ = select.select([fd], [], [], 60)
    if not ready:
        break
    try:
        chunk = os.read(fd, 4096)
    except OSError:
        break
    if not chunk:
        break
    data += chunk
    if not sent and b'Identity passphrase:' in data:
        os.write(fd, passphrase.encode() + b'\\n')
        sent = True
_, status = os.waitpid(pid, 0)
sys.stdout.buffer.write(data)
sys.exit(os.waitstatus_to_exitcode(status))
`;
  return new Promise((resolve, reject) => {
    const child = spawn('python3', ['-c', script, process.execPath, new URL('../src/cli.ts', import.meta.url).pathname, ...args, '--home', bridge.home, '--port', String(bridge.port), '--approval-port', String(bridge.approvalPort), '--json'], {
      env: { ...process.env, AGB_TEST_PASSPHRASE: passphrase },
    });
    const out: Buffer[] = [];
    child.stdout.on('data', (chunk: Buffer) => out.push(chunk));
    child.stderr.on('data', () => undefined);
    child.on('error', reject);
    child.on('close', (code) => resolve({ code: code ?? 1, stdout: Buffer.concat(out).toString('utf8') }));
  });
}

async function waitFor<T>(fn: () => Promise<T | undefined>, attempts = 20): Promise<T> {
  for (let i = 0; i < attempts; i++) {
    const value = await fn();
    if (value) return value;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error('timed out waiting for the other bridge');
}
