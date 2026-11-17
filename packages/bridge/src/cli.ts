#!/usr/bin/env node
// `agb` — thin client of the bridge daemon. Human commands read the identity
// passphrase from the TTY and post it to the loopback approval port. They
// refuse to run without a TTY, and they never take the passphrase as a flag.

import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import { stdin, stdout } from 'node:process';
import { BridgeError } from './errors.ts';
import { bridgePaths, initBridge } from './bridge.ts';
import { fingerprint } from './fingerprint.ts';

const args = process.argv.slice(2);
const flags = takeFlags(args);
const [command, sub, ...rest] = args;
const home = flags.home ?? `${process.env.HOME ?? ''}/.agent-bridge`;
const port = Number(flags.port ?? '8787');
const approvalPort = Number(flags['approval-port'] ?? String(port + 1));
const json = flags.json === 'true';

try {
  const result = await run();
  if (json) stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  else if (result !== undefined) stdout.write(`${typeof result === 'string' ? result : JSON.stringify(result, null, 2)}\n`);
} catch (err) {
  const error = err instanceof BridgeError ? err : new BridgeError('mls_error', err instanceof Error ? err.message : 'command failed', 500);
  stdout.write(`${JSON.stringify(error.body())}\n`);
  process.exitCode = 1;
}

async function run(): Promise<unknown> {
  if (command === 'init') {
    const handle = need(flags.handle, '--handle');
    const relay = need(flags.relay, '--relay');
    const passphrase = await promptPassphrase('Identity passphrase: ');
    const again = await promptPassphrase('Repeat passphrase: ');
    if (passphrase !== again) throw new BridgeError('invalid_passphrase', 'passphrases did not match', 401);
    return initBridge({ home, handle, relayOrigin: relay, passphrase });
  }
  if (command === 'fingerprint') {
    return localFingerprint(home);
  }
  if (command === 'serve') {
    const { openBridge } = await import('./bridge.ts');
    const bridge = await openBridge({ home, serve: { host: '127.0.0.1', port, approvalPort } });
    stdout.write(`agb listening on 127.0.0.1:${bridge.port} (approvals ${bridge.approvalPort})\n`);
    await new Promise(() => undefined);
  }
  if (command === 'mcp') {
    return proxyMcp(need(flags['token-file'], '--token-file'));
  }
  if (command === 'token' && sub === 'create') {
    const passphrase = await promptPassphrase('Identity passphrase: ');
    const label = rest[0];
    if (!label) throw new BridgeError('invalid_request', 'agent label is required');
    const topics = flags.all === 'true' ? '*' : (flags.topics ?? '').split(',').filter(Boolean);
    return humanPost('/tokens', { passphrase, label, topics: topics === '*' || flags.all === 'true' ? '*' : topics });
  }
  if (command === 'token' && sub === 'list') return humanGet('/tokens');
  if (command === 'token' && sub === 'revoke') {
    const passphrase = await promptPassphrase('Identity passphrase: ');
    return humanPost(`/tokens/${rest[0]}/revoke`, { passphrase });
  }
  if (command === 'approvals' && sub === 'approve') {
    const passphrase = await promptPassphrase('Identity passphrase: ');
    return humanPost(`/approvals/${rest[0]}/approve`, { passphrase });
  }
  if (command === 'approvals' && sub === 'reject') {
    const passphrase = await promptPassphrase('Identity passphrase: ');
    return humanPost(`/approvals/${rest[0]}/reject`, { passphrase });
  }
  if (command === 'approvals' && sub === 'list') {
    return authed('GET', `/v1/approvals${flags.topic ? `?topic_id=${flags.topic}` : ''}`);
  }
  if (command === 'topic' && sub === 'list') return authed('GET', '/v1/topics');
  if (command === 'topic' && sub === 'create') {
    return authed('POST', '/v1/topics', { slug: rest[0], ...(flags.title ? { title: flags.title } : {}) });
  }
  if (command === 'topic' && sub === 'sync') return authed('POST', '/v1/sync', rest[0] ? { topic_id: rest[0] } : {});
  if (command === 'topic' && sub === 'leave') {
    const passphrase = await promptPassphrase('Identity passphrase: ');
    return humanPost(`/topics/${rest[0]}/leave`, { passphrase });
  }
  if (command === 'topic' && sub === 'close') {
    const passphrase = await promptPassphrase('Identity passphrase: ');
    return humanPost(`/topics/${rest[0]}/close`, { passphrase });
  }
  if (command === 'member' && sub === 'list') return authed('GET', `/v1/topics/${rest[0]}/members`);
  if (command === 'member' && sub === 'invite') return authed('POST', `/v1/topics/${rest[0]}/invites`, { handle: rest[1] });
  if (command === 'member' && sub === 'remove') {
    return authed('POST', `/v1/topics/${rest[0]}/removals`, { handle: rest[1], ...(flags.reason ? { reason: flags.reason } : {}) });
  }
  if (command === 'msg' && sub === 'read') return authed('GET', `/v1/topics/${rest[0]}/messages`);
  if (command === 'msg' && sub === 'post') {
    return authed('POST', `/v1/topics/${rest[0]}/messages`, {
      type: rest[1],
      body: flags.body ?? '',
      ...(flags.payload ? { payload: JSON.parse(readFileSync(flags.payload, 'utf8')) } : {}),
    });
  }
  if (command === 'state' && sub === 'get') {
    return authed('GET', `/v1/topics/${rest[0]}/state${flags.path ? `?path=${encodeURIComponent(flags.path)}` : ''}`);
  }
  if (command === 'state' && sub === 'propose') {
    return authed('POST', `/v1/topics/${rest[0]}/state/patches`, {
      base_version: Number(flags.base),
      patch: JSON.parse(readFileSync(need(flags.patch, '--patch'), 'utf8')),
      summary: need(flags.summary, '--summary'),
    });
  }
  throw new BridgeError('invalid_request', 'unknown command');
}

async function authed(method: string, path: string, body?: unknown): Promise<unknown> {
  const token = readFileSync(bridgePaths(home).cliToken, 'utf8').trim();
  const res = await fetch(`http://127.0.0.1:${port}${path}`, {
    method,
    headers: { authorization: `Bearer ${token}`, ...(body !== undefined ? { 'content-type': 'application/json' } : {}) },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
  const parsed = (await res.json()) as { error?: string; message?: string };
  if (!res.ok) throw new BridgeError(String(parsed.error ?? 'mls_error'), String(parsed.message ?? 'request failed'), res.status);
  return parsed;
}

async function humanPost(path: string, body: unknown): Promise<unknown> {
  const res = await fetch(`http://127.0.0.1:${approvalPort}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', host: `127.0.0.1:${approvalPort}` },
    body: JSON.stringify(body),
  });
  const parsed = (await res.json()) as { error?: string; message?: string };
  if (!res.ok) throw new BridgeError(String(parsed.error ?? 'mls_error'), String(parsed.message ?? 'request failed'), res.status);
  return parsed;
}

async function humanGet(path: string): Promise<unknown> {
  const res = await fetch(`http://127.0.0.1:${approvalPort}${path}`, {
    headers: { host: `127.0.0.1:${approvalPort}` },
  });
  return res.json();
}

async function proxyMcp(tokenFile: string): Promise<void> {
  const token = readFileSync(tokenFile, 'utf8').trim();
  const chunks: Buffer[] = [];
  for await (const chunk of stdin) chunks.push(chunk as Buffer);
  const text = Buffer.concat(chunks).toString('utf8');
  for (const line of text.split('\n')) {
    if (line.trim().length === 0) continue;
    const res = await fetch(`http://127.0.0.1:${port}/mcp`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${token}`,
        'content-type': 'application/json',
        accept: 'application/json',
        host: `127.0.0.1:${port}`,
      },
      body: line,
    });
    if (res.status === 202) continue;
    stdout.write(`${await res.text()}\n`);
  }
}

function localFingerprint(dir: string): { handle: string; fingerprint: string } {
  const db = new DatabaseSync(bridgePaths(dir).sqlite, { readOnly: true });
  try {
    const row = db.prepare('SELECT handle, identity_pubkey FROM identity').get() as
      | { handle: string; identity_pubkey: Uint8Array }
      | undefined;
    if (!row) throw new BridgeError('not_found', 'no identity in this home', 404);
    return { handle: row.handle, fingerprint: fingerprint(row.identity_pubkey) };
  } finally {
    db.close();
  }
}

function promptPassphrase(label: string): Promise<string> {
  if (!stdin.isTTY) {
    throw new BridgeError('invalid_passphrase', 'a TTY is required to enter the identity passphrase', 401);
  }
  stdout.write(label);
  stdin.setRawMode(true);
  return new Promise((resolve) => {
    let value = '';
    const onData = (chunk: Buffer) => {
      const text = chunk.toString('utf8');
      if (text === '\u0003') process.exit(1);
      if (text === '\r' || text === '\n') {
        stdin.setRawMode(false);
        stdin.off('data', onData);
        stdout.write('\n');
        resolve(value);
        return;
      }
      if (text === '\u007f' || text === '\b') {
        value = value.slice(0, -1);
        return;
      }
      value += text;
    };
    stdin.on('data', onData);
  });
}

function takeFlags(argv: string[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (let i = argv.length - 1; i >= 0; i--) {
    const arg = argv[i];
    if (!arg?.startsWith('--')) continue;
    const key = arg.slice(2);
    const next = argv[i + 1];
    if (next === undefined || next.startsWith('--')) out[key] = 'true';
    else {
      out[key] = next;
      argv.splice(i + 1, 1);
    }
    argv.splice(i, 1);
  }
  return out;
}

function need(value: string | undefined, flag: string): string {
  if (!value || value === 'true') throw new BridgeError('invalid_request', `${flag} is required`);
  return value;
}
