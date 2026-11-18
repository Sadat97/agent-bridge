// Loopback agent API (REST + MCP) and the human approval page on a second port.
// Agent tokens are rejected on the human port. The passphrase is typed into
// the page or at a TTY by the CLI, never as a flag or environment variable.
// Browser forms need a CSRF token; JSON from the CLI is not a browser form.

import { randomBytes, timingSafeEqual } from 'node:crypto';
import { createServer } from 'node:http';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { renderApproval, renderError, renderHome, renderResult, renderTokens } from './approval-page.ts';
import type { PageApproval } from './approval-page.ts';
import { BridgeError, toSurfaceError } from './errors.ts';
import { fingerprintQrPayload } from './fingerprint.ts';
import type { AgentCaller, Bridge } from './bridge.ts';
import { dispatch, handleMcp } from './mcp.ts';

const CSRF_COOKIE = 'agb_csrf';

export type ListenerKind = 'agent' | 'human';

export function listen(
  bridge: Bridge,
  host: string,
  port: number,
  kind: ListenerKind,
): Promise<{ port: number; close: () => Promise<void> }> {
  if (host !== '127.0.0.1') throw new BridgeError('invalid_request', 'the bridge binds to 127.0.0.1 only');
  const server = createServer((req, res) => {
    void handle(bridge, kind, req, res).catch((err: unknown) => {
      const error = toSurfaceError(err);
      if (res.headersSent) {
        res.end();
        return;
      }
      if (kind === 'human' && prefersHtml(req)) sendHtml(res, error.status, renderError(error.message));
      else send(res, error.status, error.body());
    });
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => {
      const address = server.address() as AddressInfo;
      resolve({
        port: address.port,
        close: () =>
          new Promise((done) => {
            const timer = setTimeout(done, 1000);
            server.closeAllConnections();
            server.close(() => {
              clearTimeout(timer);
              done();
            });
          }),
      });
    });
  });
}

async function handle(bridge: Bridge, kind: ListenerKind, req: IncomingMessage, res: ServerResponse): Promise<void> {
  const port = (req.socket.localPort ?? 0);
  assertLoopback(req, port);
  const url = new URL(req.url ?? '/', `http://127.0.0.1:${port}`);
  if (kind === 'human') {
    if (req.headers.authorization) throw new BridgeError('unauthorized', 'agent tokens are not accepted here', 401);
    await human(bridge, req, res, url);
    return;
  }
  const agent = authenticate(bridge, req);
  if (url.pathname === '/mcp' && req.method === 'POST') {
    await handleMcp(bridge, agent, req, res);
    return;
  }
  const body = req.method === 'GET' || req.method === 'HEAD' ? {} : await jsonBody(req);
  const result = await route(bridge, agent, req.method ?? 'GET', url, body);
  send(res, 200, result);
}

async function route(
  bridge: Bridge,
  agent: AgentCaller,
  method: string,
  url: URL,
  body: Record<string, unknown>,
): Promise<unknown> {
  const parts = url.pathname.split('/').filter(Boolean);
  if (method === 'GET' && url.pathname === '/v1/whoami') {
    return { handle: bridge.credential.handle, fingerprint: bridge.fingerprint() };
  }
  if (method === 'POST' && url.pathname === '/v1/sync') return dispatch(bridge, agent, 'sync', body);
  if (method === 'GET' && url.pathname === '/v1/approvals') {
    return dispatch(bridge, agent, 'list_approvals', {
      ...(url.searchParams.get('topic_id') ? { topic_id: url.searchParams.get('topic_id') } : {}),
      ...(url.searchParams.get('status') ? { status: url.searchParams.get('status') } : {}),
    });
  }
  if (method === 'GET' && parts[0] === 'v1' && parts[1] === 'approvals' && parts.length === 3 && parts[2]) {
    return bridge.approvalDetail(agent, decodeURIComponent(parts[2]));
  }
  if (parts[0] !== 'v1' || parts[1] !== 'topics') throw new BridgeError('not_found', 'no such route', 404);
  if (parts.length === 2 && method === 'GET') {
    return dispatch(bridge, agent, 'list_topics', { include_closed: url.searchParams.get('include_closed') === 'true' });
  }
  if (parts.length === 2 && method === 'POST') return dispatch(bridge, agent, 'create_topic', body);
  const topicId = parts[2];
  if (!topicId) throw new BridgeError('not_found', 'no such route', 404);
  const tail = parts.slice(3).join('/');
  if (tail === 'members' && method === 'GET') return dispatch(bridge, agent, 'list_members', { topic_id: topicId });
  if (tail === 'invites' && method === 'POST') return dispatch(bridge, agent, 'invite_member', { topic_id: topicId, ...body });
  if (tail === 'removals' && method === 'POST') return dispatch(bridge, agent, 'remove_member', { topic_id: topicId, ...body });
  if (tail === 'messages' && method === 'GET') {
    return dispatch(bridge, agent, 'read_messages', {
      topic_id: topicId,
      ...(url.searchParams.get('since_seq') ? { since_seq: Number(url.searchParams.get('since_seq')) } : {}),
      ...(url.searchParams.get('limit') ? { limit: Number(url.searchParams.get('limit')) } : {}),
    });
  }
  if (tail === 'messages' && method === 'POST') return dispatch(bridge, agent, 'post_message', { topic_id: topicId, ...body });
  if (tail === 'state' && method === 'GET') {
    return dispatch(bridge, agent, 'get_state', {
      topic_id: topicId,
      ...(url.searchParams.get('path') ? { path: url.searchParams.get('path') } : {}),
    });
  }
  if (tail === 'state/patches' && method === 'POST') {
    return dispatch(bridge, agent, 'propose_state_change', { topic_id: topicId, ...body });
  }
  throw new BridgeError('not_found', 'no such route', 404);
}

async function human(bridge: Bridge, req: IncomingMessage, res: ServerResponse, url: URL): Promise<void> {
  const parts = url.pathname.split('/').filter(Boolean);
  const json = isJson(req);
  if (req.method === 'GET' && !json && url.pathname !== '/tokens' && url.pathname !== '/tokens/list') {
    const csrf = newCsrf();
    if (url.pathname === '/') {
      sendHtml(res, 200, renderHome(await homeModel(bridge, csrf)), csrf);
      return;
    }
    if (parts[0] === 'approvals' && parts.length === 2 && parts[1]) {
      const approval = (await bridge.humanApproval(decodeURIComponent(parts[1]))) as unknown as PageApproval;
      sendHtml(res, 200, renderApproval({ csrf, approval }), csrf);
      return;
    }
  }
  if (!json && req.method === 'POST') {
    const form = await formFields(req);
    assertCsrf(req, form.csrf ?? '');
    const passphrase = form.passphrase ?? '';
    if (url.pathname === '/tokens/list') {
      if (!passphrase) throw new BridgeError('invalid_passphrase', 'passphrase is required', 401);
      bridge.provePassphrase(passphrase);
      sendHtml(res, 200, renderTokens(bridge.listTokens()));
      return;
    }
    if (url.pathname === '/contacts/verify') {
      const handle = form.handle ?? '';
      const view = bridge.verifyContact(handle, form.fingerprint ?? '', passphrase);
      sendHtml(res, 200, renderResult('Contact', verifyMessage(view)));
      return;
    }
    if (parts[0] === 'contacts' && parts[2] === 'verify' && parts[1]) {
      const view = bridge.verifyContact(decodeURIComponent(parts[1]), form.fingerprint ?? '', passphrase);
      sendHtml(res, 200, renderResult('Contact', verifyMessage(view)));
      return;
    }
    if (parts[0] === 'approvals' && parts.length === 2 && parts[1]) {
      if (!passphrase) throw new BridgeError('invalid_passphrase', 'passphrase is required', 401);
      const id = decodeURIComponent(parts[1]);
      if (form.decision === 'deny' || form.decision === 'reject') {
        await bridge.reject(id, passphrase);
        sendHtml(res, 200, renderResult('Denied', 'The approval was denied. Nothing was sent.'));
        return;
      }
      if (form.decision === 'approve') {
        const result = await bridge.approve(id, passphrase);
        sendHtml(res, 200, renderResult('Approved', `Status: ${result.status}.`));
        return;
      }
      throw new BridgeError('invalid_request', 'decision must be approve or deny');
    }
    throw new BridgeError('not_found', 'no such route', 404);
  }
  if ((req.method === 'GET' || req.method === 'POST') && (url.pathname === '/tokens' && req.method === 'GET' || url.pathname === '/tokens/list')) {
    const body = await jsonBody(req);
    const passphrase = typeof body.passphrase === 'string' ? body.passphrase : undefined;
    if (!passphrase) throw new BridgeError('invalid_passphrase', 'passphrase is required', 401);
    bridge.provePassphrase(passphrase);
    send(res, 200, { tokens: bridge.listTokens() });
    return;
  }
  const body = await jsonBody(req);
  const passphrase = typeof body.passphrase === 'string' ? body.passphrase : undefined;
  if (parts[0] === 'approvals' && parts[2] === 'approve' && req.method === 'POST') {
    if (!passphrase || !parts[1]) throw new BridgeError('invalid_passphrase', 'passphrase is required', 401);
    send(res, 200, await bridge.approve(decodeURIComponent(parts[1]), passphrase));
    return;
  }
  if (parts[0] === 'approvals' && (parts[2] === 'reject' || parts[2] === 'deny') && req.method === 'POST') {
    if (!passphrase || !parts[1]) throw new BridgeError('invalid_passphrase', 'passphrase is required', 401);
    await bridge.reject(decodeURIComponent(parts[1]), passphrase);
    send(res, 200, { status: 'rejected' });
    return;
  }
  if (parts[0] === 'contacts' && parts[2] === 'verify' && req.method === 'POST') {
    if (!passphrase || !parts[1]) throw new BridgeError('invalid_passphrase', 'passphrase is required', 401);
    const fingerprint = typeof body.fingerprint === 'string' ? body.fingerprint : '';
    send(res, 200, bridge.verifyContact(decodeURIComponent(parts[1]), fingerprint, passphrase));
    return;
  }
  if (parts[0] === 'topics' && parts[2] === 'leave' && req.method === 'POST') {
    if (!passphrase || !parts[1]) throw new BridgeError('invalid_passphrase', 'passphrase is required', 401);
    send(res, 200, { seq: await bridge.leaveTopic(parts[1], passphrase) });
    return;
  }
  if (parts[0] === 'topics' && parts[2] === 'close' && req.method === 'POST') {
    if (!passphrase || !parts[1]) throw new BridgeError('invalid_passphrase', 'passphrase is required', 401);
    await bridge.closeTopic(parts[1], passphrase);
    send(res, 200, { status: 'closed' });
    return;
  }
  if (req.method === 'POST' && url.pathname === '/tokens') {
    if (!passphrase) throw new BridgeError('invalid_passphrase', 'passphrase is required', 401);
    bridge.provePassphrase(passphrase);
    const topics = body.topics === '*' || body.all === true ? '*' : Array.isArray(body.topics) ? body.topics.filter((item) => typeof item === 'string') : [];
    const token = bridge.createToken(String(body.label ?? ''), topics as '*' | string[]);
    send(res, 201, { token, agent_label: body.label });
    return;
  }
  if (parts[0] === 'tokens' && parts[2] === 'revoke' && req.method === 'POST') {
    if (!passphrase || !parts[1]) throw new BridgeError('invalid_passphrase', 'passphrase is required', 401);
    bridge.provePassphrase(passphrase);
    bridge.revokeToken(parts[1]);
    send(res, 200, { revoked: parts[1] });
    return;
  }
  throw new BridgeError('not_found', 'no such route', 404);
}

function verifyMessage(view: { handle: string; key_changed: boolean }): string {
  if (view.key_changed) {
    return `${view.handle} matches the pinned key. The new key is still untrusted until you verify that fingerprint.`;
  }
  return `${view.handle} is verified.`;
}

async function homeModel(bridge: Bridge, csrf: string) {
  const approvals = (await Promise.all(
    bridge.humanApprovals('pending').map((item) => bridge.humanApproval(String(item.approval_id))),
  )) as unknown as PageApproval[];
  return {
    csrf,
    handle: bridge.credential.handle,
    fingerprint: bridge.fingerprint(),
    qrPayload: fingerprintQrPayload(bridge.credential.identityKey),
    approvals,
    contacts: bridge.listContacts(),
  };
}

function authenticate(bridge: Bridge, req: IncomingMessage): AgentCaller {
  const header = req.headers.authorization;
  const match = typeof header === 'string' ? /^Bearer (\S+)$/.exec(header) : null;
  if (!match) throw new BridgeError('unauthorized', 'bearer token is required', 401);
  const agent = bridge.agentForToken(match[1] ?? '');
  if (!agent) throw new BridgeError('unauthorized', 'bearer token is not valid', 401);
  return agent;
}

function assertLoopback(req: IncomingMessage, port: number): void {
  const host = req.headers.host?.toLowerCase();
  const allowedHosts = new Set([`127.0.0.1:${port}`, `localhost:${port}`]);
  if (!host || !allowedHosts.has(host)) throw new BridgeError('unauthorized', 'host is not loopback', 401);
  const origin = req.headers.origin;
  if (origin !== undefined) {
    const allowed = new Set([`http://127.0.0.1:${port}`, `http://localhost:${port}`]);
    if (!allowed.has(origin)) throw new BridgeError('unauthorized', 'origin is not allowed', 403);
  }
}

async function jsonBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  if (chunks.length === 0) return {};
  try {
    const value = JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown;
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
      throw new BridgeError('invalid_request', 'body must be a JSON object');
    }
    return value as Record<string, unknown>;
  } catch (err) {
    if (err instanceof BridgeError) throw err;
    throw new BridgeError('invalid_request', 'body is not JSON');
  }
}

function send(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) });
  res.end(payload);
}

function sendHtml(res: ServerResponse, status: number, html: string, csrf?: string): void {
  const headers: Record<string, string | number> = {
    'content-type': 'text/html; charset=utf-8',
    'content-length': Buffer.byteLength(html),
    'cache-control': 'no-store',
    'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; form-action 'self'; base-uri 'none'",
    'referrer-policy': 'no-referrer',
    'x-content-type-options': 'nosniff',
  };
  if (csrf) headers['set-cookie'] = `${CSRF_COOKIE}=${csrf}; HttpOnly; SameSite=Strict; Path=/`;
  res.writeHead(status, headers);
  res.end(html);
}

function prefersHtml(req: IncomingMessage): boolean {
  const type = contentType(req);
  if (type.includes('application/json')) return false;
  return req.method === 'GET' || type.includes('application/x-www-form-urlencoded');
}

function isJson(req: IncomingMessage): boolean {
  return contentType(req).includes('application/json');
}

function contentType(req: IncomingMessage): string {
  const value = req.headers['content-type'];
  return typeof value === 'string' ? value.toLowerCase() : '';
}

function newCsrf(): string {
  return randomBytes(32).toString('base64url');
}

function assertCsrf(req: IncomingMessage, formToken: string): void {
  const fromCookie = readCookie(req, CSRF_COOKIE);
  if (!fromCookie || !formToken || fromCookie.length !== formToken.length) {
    throw new BridgeError('unauthorized', 'csrf token is not valid', 403);
  }
  const left = Buffer.from(fromCookie);
  const right = Buffer.from(formToken);
  if (left.length !== right.length || !timingSafeEqual(left, right)) {
    throw new BridgeError('unauthorized', 'csrf token is not valid', 403);
  }
}

function readCookie(req: IncomingMessage, name: string): string | undefined {
  const header = req.headers.cookie;
  if (!header) return undefined;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim();
  }
  return undefined;
}

async function formFields(req: IncomingMessage): Promise<Record<string, string>> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const buf = chunk as Buffer;
    size += buf.length;
    if (size > 65_536) throw new BridgeError('invalid_request', 'form is too large');
    chunks.push(buf);
  }
  const params = new URLSearchParams(Buffer.concat(chunks).toString('utf8'));
  const out: Record<string, string> = {};
  for (const [key, value] of params) out[key] = value;
  return out;
}
