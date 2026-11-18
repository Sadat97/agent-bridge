#!/usr/bin/env node
// `agb` — thin client of the bridge daemon. Human commands read the identity
// passphrase from the TTY and post it to the loopback approval port. They
// refuse to run without a TTY, and they never take the passphrase as a flag.

import { DatabaseSync } from 'node:sqlite';
import { readFileSync, writeSync } from 'node:fs';
import { stdin, stdout } from 'node:process';
import { BridgeError } from './errors.ts';
import { bridgePaths, initBridge } from './bridge.ts';
import { fingerprint, fingerprintQrPayload, parseFingerprint } from './fingerprint.ts';
import { readContacts } from './local.ts';
import type { ContactRecord } from './local.ts';
import { qrTerminal } from './qr.ts';

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
// A TTY stays open after the passphrase prompt. Don't wait for the terminal to close.
stdin.pause();
stdin.unref();

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
    const shown = sub ? contactFingerprint(home, sub) : localFingerprint(home);
    if (json) return { handle: shown.handle, fingerprint: shown.fingerprint, qr_payload: fingerprintQrPayload(shown.publicKey) };
    return textFingerprint(shown);
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
  if (command === 'token' && sub === 'list') {
    const passphrase = await promptPassphrase('Identity passphrase: ');
    return humanPost('/tokens/list', { passphrase });
  }
  if (command === 'token' && sub === 'revoke') {
    const passphrase = await promptPassphrase('Identity passphrase: ');
    return humanPost(`/tokens/${rest[0]}/revoke`, { passphrase });
  }
  if (command === 'approvals' && sub === 'approve') {
    const passphrase = await promptPassphrase('Identity passphrase: ');
    return humanPost(`/approvals/${need(rest[0], 'approval id')}/approve`, { passphrase });
  }
  if (command === 'approvals' && (sub === 'reject' || sub === 'deny')) {
    const passphrase = await promptPassphrase('Identity passphrase: ');
    return humanPost(`/approvals/${need(rest[0], 'approval id')}/reject`, { passphrase });
  }
  if (command === 'approvals' && sub === 'show') {
    const detail = await authed('GET', `/v1/approvals/${encodeURIComponent(need(rest[0], 'approval id'))}`);
    if (json) return detail;
    return textApproval(detail);
  }
  if (command === 'approvals' && sub === 'list') {
    const query = new URLSearchParams();
    if (flags.topic) query.set('topic_id', flags.topic);
    if (flags.status) query.set('status', flags.status);
    const suffix = query.size > 0 ? `?${query.toString()}` : '';
    const listed = await authed('GET', `/v1/approvals${suffix}`);
    if (json) return listed;
    return textApprovalList(listed);
  }
  if (command === 'contact' && sub === 'list') {
    const contacts = readContacts(bridgePaths(home).sqlite)
      .filter((contact) => contact.handle !== localFingerprint(home).handle)
      .map(contactText);
    if (json) return { contacts };
    if (contacts.length === 0) return 'No contacts pinned yet.';
    return contacts.map((contact) => `${contact.handle}  ${contact.state}  ${contact.fingerprint}`).join('\n');
  }
  if (command === 'contact' && sub === 'show') {
    const contact = contactText(needContact(home, need(rest[0], 'handle')));
    if (json) return contact;
    const lines = [
      `${contact.handle}  ${contact.state}`,
      contact.fingerprint,
      qrTerminal(contact.qr_payload),
    ];
    if (contact.pending_fingerprint && contact.pending_qr_payload) {
      lines.push('KEY CHANGED. This contact is blocked until you verify the new fingerprint.', contact.pending_fingerprint, qrTerminal(contact.pending_qr_payload));
    }
    return lines.join('\n');
  }
  if (command === 'contact' && sub === 'verify') {
    const handle = need(rest[0], 'handle');
    const presented = rest.slice(1).join(' ');
    if (!parseFingerprint(presented)) {
      throw new BridgeError('invalid_request', 'fingerprint must be 60 digits or an agbfp:v1 QR payload');
    }
    const passphrase = await promptPassphrase('Identity passphrase: ');
    return humanPost(`/contacts/${encodeURIComponent(handle)}/verify`, { passphrase, fingerprint: presented });
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

function localFingerprint(dir: string): { handle: string; fingerprint: string; publicKey: Uint8Array } {
  const db = new DatabaseSync(bridgePaths(dir).sqlite, { readOnly: true });
  try {
    const row = db.prepare('SELECT handle, identity_pubkey FROM identity').get() as
      | { handle: string; identity_pubkey: Uint8Array }
      | undefined;
    if (!row) throw new BridgeError('not_found', 'no identity in this home', 404);
    const publicKey = new Uint8Array(row.identity_pubkey);
    return { handle: row.handle, fingerprint: fingerprint(publicKey), publicKey };
  } finally {
    db.close();
  }
}

function contactFingerprint(dir: string, handle: string): { handle: string; fingerprint: string; publicKey: Uint8Array } {
  const contact = needContact(dir, handle);
  return { handle: contact.handle, fingerprint: fingerprint(contact.identityKey), publicKey: contact.identityKey };
}

function needContact(dir: string, handle: string): ContactRecord {
  const contact = readContacts(bridgePaths(dir).sqlite).find((row) => row.handle === handle);
  if (!contact) throw new BridgeError('not_found', 'no such contact', 404);
  return contact;
}

function contactText(contact: ContactRecord): {
  handle: string;
  state: string;
  fingerprint: string;
  qr_payload: string;
  pending_fingerprint: string | null;
  pending_qr_payload: string | null;
  verified: boolean;
  key_changed: boolean;
} {
  const keyChanged = contact.pendingKey !== null;
  const verified = !keyChanged && contact.verifiedAt !== null;
  return {
    handle: contact.handle,
    state: keyChanged ? 'key changed' : verified ? 'verified' : 'unverified',
    fingerprint: fingerprint(contact.identityKey),
    qr_payload: fingerprintQrPayload(contact.identityKey),
    pending_fingerprint: contact.pendingKey ? fingerprint(contact.pendingKey) : null,
    pending_qr_payload: contact.pendingKey ? fingerprintQrPayload(contact.pendingKey) : null,
    verified,
    key_changed: keyChanged,
  };
}

function textFingerprint(shown: { handle: string; fingerprint: string; publicKey: Uint8Array }): string {
  return `${shown.handle}\n${shown.fingerprint}\n${qrTerminal(fingerprintQrPayload(shown.publicKey))}`;
}

function textApprovalList(body: unknown): string {
  const items = isRecord(body) && Array.isArray(body.items) ? body.items : [];
  if (items.length === 0) return 'No approvals.';
  return items
    .map((item) => {
      if (!isRecord(item)) return '';
      const hold = typeof item.hold === 'string' ? item.hold : item.kind;
      return `${item.approval_id}  ${item.status}  ${hold}  ${item.requested_by}\n  ${item.summary}`;
    })
    .filter((line) => line.length > 0)
    .join('\n');
}

function textApproval(body: unknown): string {
  if (!isRecord(body)) return JSON.stringify(body);
  const lines = [
    `${body.approval_id}  ${body.status}  ${body.hold ?? body.kind}`,
    String(body.summary ?? ''),
    `requested by ${body.requested_by}`,
  ];
  if (typeof body.topic_title === 'string' && body.topic_title) lines.push(`topic ${body.topic_title}`);
  if (Array.isArray(body.sensitive_paths) && body.sensitive_paths.length > 0) {
    lines.push(`sensitive paths ${body.sensitive_paths.join(', ')}`);
  }
  lines.push(JSON.stringify(body.request ?? {}, null, 2));
  const contact = isRecord(body.contact) ? body.contact : undefined;
  if (contact && typeof contact.fingerprint === 'string' && typeof contact.qr_payload === 'string') {
    const state = contact.key_changed ? 'KEY CHANGED' : contact.verified ? 'verified' : 'unverified';
    lines.push(`${contact.handle}  ${state}`, contact.fingerprint, qrTerminal(contact.qr_payload));
    if (typeof contact.pending_fingerprint === 'string' && typeof contact.pending_qr_payload === 'string') {
      lines.push('New fingerprint. Verify it before approving.', contact.pending_fingerprint, qrTerminal(contact.pending_qr_payload));
    }
  }
  return lines.join('\n');
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function promptPassphrase(label: string): Promise<string> {
  if (!stdin.isTTY) {
    throw new BridgeError('invalid_passphrase', 'a TTY is required to enter the identity passphrase', 401);
  }
  stdin.setRawMode(true);
  let value = '';
  const result = new Promise<string>((resolve) => {
    const onData = (chunk: Buffer) => {
      const text = chunk.toString('utf8');
      if (text === '\u0003') process.exit(1);
      if (text.includes('\r') || text.includes('\n')) {
        const end = text.search(/\r|\n/);
        value += text.slice(0, end);
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
  // Write the prompt after the listener is attached. A fast terminal can
  // answer before a later `on('data')` would run.
  writeSync(1, label);
  return result;
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
