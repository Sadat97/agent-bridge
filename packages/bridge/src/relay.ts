// Relay HTTP and WebSocket client. Login is the device-key challenge from
// section 8.4. The signed origin is the relay's public origin, which may
// differ from the URL we dial (a local test relay does this).

import {
  SignatureLabel,
  fromBase64,
  relayAuthContent,
  signWithLabel,
  toBase64,
} from '@agent-bridge/protocol';
import type { StagedOutbound } from '@agent-bridge/mls';
import WebSocket from 'ws';
import { BridgeError } from './errors.ts';

export interface RelayMessage {
  seq: number;
  epoch: number;
  senderDevice: string;
  bytes: Uint8Array;
}

export interface RelayAccount {
  handle: string;
  identityKey: Uint8Array;
  devices: Array<{ deviceId: string; signatureKey: Uint8Array; cert: Uint8Array; revoked: boolean }>;
}

export interface RelayTopic {
  topicId: string;
  owner: string;
  role: string;
  epoch: number;
  lastSeq: number;
  closedAt: string | null;
  stale: boolean;
  members: Array<{ deviceId: string; handle: string; role: string }>;
}

export interface RelayWelcome {
  id: string;
  topicId: string;
  commitSeq: number;
  welcome: Uint8Array;
}

export type RelayEvent =
  | { type: 'message'; topic_id: string; seq: number; message?: string }
  | { type: 'welcome'; id: string; topic_id: string; commit_seq: number }
  | { type: 'member_stale'; topic_id: string; device_id: string }
  | { type: 'key_packages_low'; count: number }
  | { type: 'pong' };

type PostResult =
  | { ok: true; seq: number; epoch: number }
  | { ok: false; status: number; code: string; message: string };

export class RelayClient {
  readonly relayUrl: string;
  readonly relayOrigin: string;
  readonly deviceId: string;
  readonly #privateKey: Uint8Array;
  #token = '';
  #expiresAt = 0;

  constructor(opts: { relayUrl: string; relayOrigin: string; deviceId: string; devicePrivateKey: Uint8Array }) {
    this.relayUrl = opts.relayUrl.replace(/\/$/, '');
    this.relayOrigin = opts.relayOrigin;
    this.deviceId = opts.deviceId;
    this.#privateKey = opts.devicePrivateKey;
  }

  async register(body: {
    handle: string;
    identityKey: Uint8Array;
    deviceId: string;
    signatureKey: Uint8Array;
    cert: Uint8Array;
  }): Promise<void> {
    const res = await this.#request('POST', '/v1/accounts', {
      handle: body.handle,
      identity_pubkey: toBase64(body.identityKey),
      device: {
        id: body.deviceId,
        signature_pubkey: toBase64(body.signatureKey),
        cert: toBase64(body.cert),
      },
    });
    if (res.status !== 201) throw relayError(res.status, res.body);
  }

  async login(): Promise<void> {
    const challenge = await this.#request('POST', '/v1/auth/challenge', { device_id: this.deviceId });
    if (challenge.status !== 200) throw relayError(challenge.status, challenge.body);
    const nonce = fromBase64(str(challenge.body, 'nonce'));
    if (!nonce) throw new BridgeError('relay_unavailable', 'relay challenge was not base64', 503);
    const signature = signWithLabel(this.#privateKey, SignatureLabel.relayAuth, relayAuthContent(this.relayOrigin, nonce));
    const token = await this.#request('POST', '/v1/auth/token', {
      device_id: this.deviceId,
      nonce: str(challenge.body, 'nonce'),
      signature: toBase64(signature),
    });
    if (token.status !== 200) throw relayError(token.status, token.body);
    this.#token = str(token.body, 'access_token');
    this.#expiresAt = Date.parse(str(token.body, 'expires_at'));
  }

  async createTopic(topicId: string): Promise<void> {
    const res = await this.#authed('POST', '/v1/topics', { id: topicId });
    if (res.status !== 201) throw relayError(res.status, res.body);
  }

  async topic(topicId: string): Promise<RelayTopic> {
    const res = await this.#authed('GET', `/v1/topics/${topicId}`);
    if (res.status !== 200) throw relayError(res.status, res.body);
    const members = Array.isArray(res.body.members) ? res.body.members : [];
    return {
      topicId: str(res.body, 'topic_id'),
      owner: str(res.body, 'owner'),
      role: str(res.body, 'role'),
      epoch: num(res.body, 'epoch'),
      lastSeq: num(res.body, 'last_seq'),
      closedAt: res.body.closed_at === null || res.body.closed_at === undefined ? null : String(res.body.closed_at),
      stale: res.body.stale === true,
      members: members.map((member) => {
        const row = member as Record<string, unknown>;
        return { deviceId: str(row, 'device_id'), handle: str(row, 'handle'), role: str(row, 'role') };
      }),
    };
  }

  async account(handle: string): Promise<RelayAccount> {
    const res = await this.#authed('GET', `/v1/accounts/${encodeURIComponent(handle)}`);
    if (res.status !== 200) throw relayError(res.status, res.body);
    const identity = fromBase64(str(res.body, 'identity_pubkey'));
    if (!identity) throw new BridgeError('relay_unavailable', 'account key was not base64', 503);
    const devices = Array.isArray(res.body.devices) ? res.body.devices : [];
    return {
      handle: str(res.body, 'handle'),
      identityKey: identity,
      devices: devices.map((device) => {
        const row = device as Record<string, unknown>;
        return {
          deviceId: str(row, 'device_id'),
          signatureKey: fromBase64(str(row, 'signature_pubkey')) ?? new Uint8Array(),
          cert: fromBase64(str(row, 'cert')) ?? new Uint8Array(),
          revoked: row.revoked === true,
        };
      }),
    };
  }

  async uploadKeyPackages(packages: Uint8Array[]): Promise<number> {
    const res = await this.#authed('POST', '/v1/key-packages', {
      key_packages: packages.map((pack) => toBase64(pack)),
    });
    if (res.status !== 200) throw relayError(res.status, res.body);
    return num(res.body, 'unclaimed');
  }

  async keyPackageCount(): Promise<number> {
    const res = await this.#authed('GET', '/v1/key-packages/count');
    if (res.status !== 200) throw relayError(res.status, res.body);
    return num(res.body, 'unclaimed');
  }

  async claim(
    deviceId: string,
    body: { topicId: string; approvalId: string; expiresAt: number; approval: Uint8Array },
  ): Promise<Uint8Array> {
    const res = await this.#authed('POST', `/v1/devices/${deviceId}/key-packages/claim`, {
      topic_id: body.topicId,
      approval_id: body.approvalId,
      expires_at: body.expiresAt,
      approval: toBase64(body.approval),
    });
    if (res.status !== 200) throw relayError(res.status, res.body);
    const pack = fromBase64(str(res.body, 'key_package'));
    if (!pack) throw new BridgeError('relay_unavailable', 'claimed KeyPackage was not base64', 503);
    return pack;
  }

  async post(topicId: string, staged: StagedOutbound): Promise<PostResult> {
    const body: Record<string, unknown> = { message: toBase64(staged.message) };
    if (staged.adds.length > 0 || staged.removes.length > 0) {
      body.membership = {
        adds: staged.adds.map((add) => ({
          device_id: add.deviceId,
          approval_id: add.approvalId,
          expires_at: add.expiresAt,
          approval: toBase64(add.approval),
        })),
        removes: staged.removes.map((remove) => ({
          device_id: remove.deviceId,
          approval_id: remove.approvalId,
          ...(remove.approval ? { approval: toBase64(remove.approval) } : {}),
          ...(remove.leaveSeq !== null ? { leave_seq: remove.leaveSeq } : {}),
        })),
      };
    }
    if (staged.welcome) {
      body.welcome = {
        message: toBase64(staged.welcome),
        recipients: staged.adds.map((add) => add.deviceId),
      };
    }
    const res = await this.#authed('POST', `/v1/topics/${topicId}/messages`, body);
    if (res.status === 201) return { ok: true, seq: num(res.body, 'seq'), epoch: num(res.body, 'epoch') };
    return {
      ok: false,
      status: res.status,
      code: typeof res.body.error === 'string' ? res.body.error : 'relay_unavailable',
      message: typeof res.body.message === 'string' ? res.body.message : 'relay rejected the message',
    };
  }

  async messages(topicId: string, afterSeq: number): Promise<RelayMessage[]> {
    const res = await this.#authed('GET', `/v1/topics/${topicId}/messages?after_seq=${afterSeq}&limit=100`);
    if (res.status !== 200) throw relayError(res.status, res.body);
    const rows = Array.isArray(res.body.messages) ? res.body.messages : [];
    const out: RelayMessage[] = [];
    for (const row of rows) {
      const record = row as Record<string, unknown>;
      const bytes = fromBase64(str(record, 'message'));
      if (!bytes) continue;
      out.push({
        seq: num(record, 'seq'),
        epoch: num(record, 'epoch'),
        senderDevice: str(record, 'sender_device'),
        bytes,
      });
    }
    return out;
  }

  async inbox(): Promise<RelayWelcome[]> {
    const res = await this.#authed('GET', '/v1/inbox');
    if (res.status !== 200) throw relayError(res.status, res.body);
    const rows = Array.isArray(res.body.welcomes) ? res.body.welcomes : [];
    const out: RelayWelcome[] = [];
    for (const row of rows) {
      const record = row as Record<string, unknown>;
      const welcome = fromBase64(str(record, 'welcome'));
      if (!welcome) continue;
      out.push({
        id: str(record, 'id'),
        topicId: str(record, 'topic_id'),
        commitSeq: num(record, 'commit_seq'),
        welcome,
      });
    }
    return out;
  }

  async ackWelcome(id: string): Promise<void> {
    const res = await this.#authed('POST', `/v1/inbox/${id}/ack`);
    if (res.status !== 200) throw relayError(res.status, res.body);
  }

  async closeTopic(topicId: string): Promise<void> {
    const res = await this.#authed('POST', `/v1/topics/${topicId}/close`);
    if (res.status !== 200) throw relayError(res.status, res.body);
  }

  connect(onEvent: (event: RelayEvent) => void): WebSocket {
    const socket = new WebSocket(this.relayUrl.replace(/^http/, 'ws') + '/v1/ws', {
      headers: { authorization: `Bearer ${this.#token}` },
    });
    socket.on('message', (raw) => {
      let parsed: unknown;
      try {
        parsed = JSON.parse(raw.toString());
      } catch {
        return;
      }
      if (!parsed || typeof parsed !== 'object' || !('type' in parsed)) return;
      onEvent(parsed as RelayEvent);
    });
    return socket;
  }

  sendAck(socket: WebSocket, topicId: string, seq: number): void {
    if (socket.readyState !== WebSocket.OPEN) return;
    socket.send(JSON.stringify({ type: 'ack', topic_id: topicId, seq }));
  }

  async #authed(method: string, path: string, body?: unknown): Promise<RelayResponse> {
    if (this.#expiresAt - Date.now() < 30_000) await this.login();
    const res = await this.#request(method, path, body, this.#token);
    if (res.status !== 401) return res;
    await this.login();
    return this.#request(method, path, body, this.#token);
  }

  async #request(method: string, path: string, body?: unknown, token?: string): Promise<RelayResponse> {
    const headers: Record<string, string> = {};
    if (body !== undefined) headers['content-type'] = 'application/json';
    if (token) headers.authorization = `Bearer ${token}`;
    let res: Response;
    try {
      res = await fetch(this.relayUrl + path, {
        method,
        headers,
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      });
    } catch {
      throw new BridgeError('relay_unavailable', 'the relay could not be reached', 503);
    }
    const text = await res.text();
    let parsed: Record<string, unknown> = {};
    if (text.length > 0) {
      try {
        const value = JSON.parse(text) as unknown;
        if (value && typeof value === 'object') parsed = value as Record<string, unknown>;
      } catch {
        parsed = { message: 'relay returned a non-JSON body' };
      }
    }
    return { status: res.status, body: parsed };
  }
}

interface RelayResponse {
  status: number;
  body: Record<string, unknown>;
}

function relayError(status: number, body: Record<string, unknown>): BridgeError {
  const code = typeof body.error === 'string' ? body.error : 'relay_unavailable';
  const message = typeof body.message === 'string' ? body.message : 'the relay rejected the request';
  const http = status === 404 ? 404 : status === 401 ? 401 : status === 409 ? 409 : 503;
  return new BridgeError(code === 'relay_unavailable' ? code : 'relay_unavailable', message, http, { relay_error: code });
}

function str(body: Record<string, unknown>, key: string): string {
  const value = body[key];
  if (typeof value !== 'string') throw new BridgeError('relay_unavailable', `relay response is missing ${key}`, 503);
  return value;
}

function num(body: Record<string, unknown>, key: string): number {
  const value = body[key];
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new BridgeError('relay_unavailable', `relay response is missing ${key}`, 503);
  }
  return value;
}
