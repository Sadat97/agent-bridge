// One person's bridge. It is the only writer of MLS state. Agents call the
// methods below through MCP, REST, or the CLI; they never open the store.

import { AsyncLocalStorage } from 'node:async_hooks';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  addApprovalContent,
  bytesEqual,
  generateEd25519KeyPair,
  issueDeviceCert,
  removeApprovalContent,
  SignatureLabel,
  signWithLabel,
  fromBase64,
  utf8,
  verifyDeviceCert,
} from '@agent-bridge/protocol';
import {
  REASON_TEXT,
  TopicSession,
  UNPUBLISHED_GENERATION_SKIP,
  createTsMlsEngine,
  replenishKeyPackages,
} from '@agent-bridge/mls';
import type { AddRequest, Credential, MlsEngine, RemoveRequest, TopicSession as Session } from '@agent-bridge/mls';
import { MlsStore } from '@agent-bridge/mls';
import { BridgeError, toSurfaceError } from './errors.ts';
import { fingerprint, fingerprintDigits, fingerprintQrPayload, parseFingerprint } from './fingerprint.ts';
import { applyPatch, hashBytes, hashLabel, pointerValue } from './json.ts';
import type { PatchOp } from './json.ts';
import { LocalStore, scrubPlaintext } from './local.ts';
import type { ApprovalRow, EnvelopeRow } from './local.ts';
import { DEFAULT_POLICY, loadPolicy, patchNeedsApproval, pathIsSensitive, requestNeedsApproval } from './policy.ts';
import { RelayClient } from './relay.ts';
import { AesGcmSealer, unwrapPassphrase, wrapPassphrase } from './seal.ts';
import { signRequest, signState } from './signatures.ts';
import type WebSocket from 'ws';

const KEY_LOW = 10;
const KEY_TARGET = 20;
const SNAPSHOT_EVERY = 50;
/** Section 5.6: a signed add is retried until this claim lifetime, not the 72-hour decision window. */
const INVITE_CLAIM_SECONDS = 7 * 24 * 60 * 60;
/** Section 5.7: a bridge commits a self-Update when it has not committed for this long. */
export const SELF_UPDATE_INTERVAL_MS = 7 * 24 * 60 * 60 * 1000;
/**
 * Longest sleep passed to `setTimeout`. Node clamps a delay above 2^31-1 ms
 * to 1 ms, which would busy-loop. Waking at least daily also notices a forward
 * clock step: the callback reads the stored deadline again instead of waiting
 * out the delay it was armed with.
 */
export const SELF_UPDATE_WAKE_CAP_MS = 24 * 60 * 60 * 1000;
const SET_TIMEOUT_MAX_MS = 2_147_483_647;

/** Delay for one arm. Never above 24h or the Node timeout ceiling. */
export function selfUpdateTimerDelay(deadlineAt: number, now = Date.now()): number {
  const remaining = Math.max(0, deadlineAt - now);
  return Math.min(remaining, SELF_UPDATE_WAKE_CAP_MS, SET_TIMEOUT_MAX_MS);
}

export interface ContactView {
  handle: string;
  fingerprint: string;
  qr_payload: string;
  verified: boolean;
  key_changed: boolean;
  pending_fingerprint: string | null;
  pending_qr_payload: string | null;
  verified_at: string | null;
}

export interface AgentCaller {
  label: string;
  topics: '*' | string[];
}

export interface BridgeConfig {
  handle: string;
  relayOrigin: string;
  relayUrl: string;
  deviceId: string;
}

export function bridgePaths(home: string): {
  home: string;
  storageKey: string;
  sqlite: string;
  policy: string;
  cliToken: string;
  config: string;
} {
  return {
    home,
    storageKey: join(home, 'storage.key'),
    sqlite: join(home, 'store.sqlite'),
    policy: join(home, 'policy.json'),
    cliToken: join(home, 'cli.token'),
    config: join(home, 'config.json'),
  };
}

export async function initBridge(opts: {
  home: string;
  handle: string;
  relayOrigin: string;
  relayUrl?: string;
  passphrase: string;
}): Promise<{ fingerprint: string; cliToken: string }> {
  const paths = bridgePaths(opts.home);
  mkdirSync(paths.home, { recursive: true, mode: 0o700 });
  chmodSync(paths.home, 0o700);
  if (exists(paths.config)) throw new BridgeError('invalid_request', 'this home is already initialized');
  const identity = generateEd25519KeyPair();
  const device = generateEd25519KeyPair();
  const deviceId = randomUUID();
  const createdAt = Math.floor(Date.now() / 1000);
  const cert = issueDeviceCert(identity.privateKey, {
    handle: opts.handle,
    deviceId,
    signatureKey: device.publicKey,
    createdAt,
  });
  const storageKey = randomBytes(32);
  const sealer = new AesGcmSealer(storageKey);
  writeSecret(paths.storageKey, storageKey);
  const mls = new MlsStore(paths.sqlite, { sealer });
  const local = new LocalStore(paths.sqlite, { sealer });
  chmodSync(paths.sqlite, 0o600);
  try {
    local.saveIdentity(opts.handle, identity.publicKey, wrapPassphrase(identity.privateKey, opts.passphrase, utf8(`identity-key:${opts.handle}`)));
    local.saveDevice(deviceId, device.publicKey, sealer.seal(device.privateKey, utf8(`device-key:${deviceId}`)), cert);
    const relay = new RelayClient({
      relayUrl: opts.relayUrl ?? opts.relayOrigin,
      relayOrigin: opts.relayOrigin,
      deviceId,
      devicePrivateKey: device.privateKey,
    });
    await relay.register({
      handle: opts.handle,
      identityKey: identity.publicKey,
      deviceId,
      signatureKey: device.publicKey,
      cert,
    });
    await relay.login();
    const credential: Credential = { handle: opts.handle, identityKey: identity.publicKey, deviceId, deviceCert: cert };
    const engine = createTsMlsEngine({ devicePrivateKey: device.privateKey, pins: mls.pins });
    const packs = await replenishKeyPackages(engine, credential, mls, KEY_TARGET);
    await relay.uploadKeyPackages(packs);
    const cliToken = issueToken(local, 'cli', '*');
    writeSecret(paths.cliToken, utf8(cliToken));
    writeFileSync(paths.policy, `${JSON.stringify(DEFAULT_POLICY, null, 2)}\n`, { mode: 0o600 });
    const config: BridgeConfig = {
      handle: opts.handle,
      relayOrigin: opts.relayOrigin,
      relayUrl: opts.relayUrl ?? opts.relayOrigin,
      deviceId,
    };
    writeFileSync(paths.config, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });
    return { fingerprint: fingerprint(identity.publicKey), cliToken };
  } finally {
    identity.privateKey.fill(0);
    device.privateKey.fill(0);
    storageKey.fill(0);
    local.close();
    mls.close();
  }
}

export async function openBridge(opts: {
  home: string;
  serve?: { host?: string; port?: number; approvalPort?: number };
}): Promise<Bridge> {
  const bridge = new Bridge(opts.home);
  await bridge.start(opts.serve);
  return bridge;
}

export class Bridge {
  readonly home: string;
  readonly paths: ReturnType<typeof bridgePaths>;
  readonly config: BridgeConfig;
  readonly local: LocalStore;
  readonly mls: MlsStore;
  readonly engine: MlsEngine;
  readonly relay: RelayClient;
  readonly credential: Credential;
  port = 0;
  approvalPort = 0;
  readonly #devicePrivate: Uint8Array;
  readonly #sessions = new Map<string, TopicSession>();
  readonly #owners = new Map<string, string>();
  readonly #queues = new Map<string, Promise<void>>();
  readonly #held = new AsyncLocalStorage<Set<string>>();
  #socket: WebSocket | undefined;
  #closed = false;
  #selfUpdateTimer: ReturnType<typeof setTimeout> | undefined;
  #nextSelfUpdateAt: number | undefined;
  #wakeDelayMs: number | undefined;
  #servers: Array<{ close: () => Promise<void> }> = [];

  constructor(home: string) {
    this.home = home;
    this.paths = bridgePaths(home);
    this.config = JSON.parse(readFileSync(this.paths.config, 'utf8')) as BridgeConfig;
    const storageKey = new Uint8Array(readFileSync(this.paths.storageKey));
    const sealer = new AesGcmSealer(storageKey);
    // Rebuild the file before the MLS connection opens, so VACUUM can run and
    // WAL/journal sidecars that still hold plaintext can be removed.
    scrubPlaintext(this.paths.sqlite, sealer);
    this.mls = new MlsStore(this.paths.sqlite, { sealer });
    this.local = new LocalStore(this.paths.sqlite, { sealer });
    chmodSync(this.paths.sqlite, 0o600);
    const device = this.local.device();
    const identity = this.local.identity();
    if (!device || !identity) throw new BridgeError('mls_error', 'this home has no device', 500);
    this.#devicePrivate = sealer.open(device.wrappedPrivate, utf8(`device-key:${device.deviceId}`));
    this.credential = {
      handle: identity.handle,
      identityKey: identity.publicKey,
      deviceId: device.deviceId,
      deviceCert: device.cert,
    };
    this.engine = createTsMlsEngine({ devicePrivateKey: this.#devicePrivate, pins: this.mls.pins });
    this.relay = new RelayClient({
      relayUrl: this.config.relayUrl,
      relayOrigin: this.config.relayOrigin,
      deviceId: device.deviceId,
      devicePrivateKey: this.#devicePrivate,
    });
    storageKey.fill(0);
  }

  async start(serve?: { host?: string; port?: number; approvalPort?: number }): Promise<void> {
    for (const topicId of this.mls.topicIds()) {
      const session = TopicSession.open(this.mls, this.engine, topicId);
      this.#bind(session);
      if (session.role === 'owner') this.#owners.set(topicId, this.credential.handle);
    }
    await this.relay.login();
    await this.#topUp();
    await this.#connectSocket();
    await this.syncAll();
    await this.runDueSelfUpdates();
    if (serve) {
      const { listen } = await import('./http.ts');
      const host = serve.host ?? '127.0.0.1';
      const agent = await listen(this, host, serve.port ?? 8787, 'agent');
      const human = await listen(this, host, serve.approvalPort ?? 8788, 'human');
      this.port = agent.port;
      this.approvalPort = human.port;
      this.#servers.push(agent, human);
    }
  }

  async close(): Promise<void> {
    this.#closed = true;
    if (this.#selfUpdateTimer) clearTimeout(this.#selfUpdateTimer);
    this.#socket?.terminate();
    await Promise.race([
      Promise.all(this.#servers.map((server) => server.close())),
      new Promise((resolve) => setTimeout(resolve, 500)),
    ]);
    this.#devicePrivate.fill(0);
    try {
      this.mls.close();
    } catch {
      // A second connection can still be checkpointing. Process exit closes the file.
    }
    try {
      this.local.close();
    } catch {
      // Same as above.
    }
  }

  fingerprint(): string {
    return fingerprint(this.credential.identityKey);
  }

  agentForToken(token: string): AgentCaller | undefined {
    const row = this.local.token(sha256(utf8(token)));
    if (!row) return undefined;
    return { label: row.label, topics: row.topics };
  }

  createToken(label: string, topics: '*' | string[]): string {
    if (!/^[a-z0-9][a-z0-9_-]{0,31}$/.test(label)) throw new BridgeError('invalid_request', 'agent label is not valid');
    if (this.local.tokens().some((token) => token.label === label && token.revokedAt === null)) {
      throw new BridgeError('invalid_request', 'agent label is already in use');
    }
    return issueToken(this.local, label, topics);
  }

  revokeToken(label: string): void {
    if (!this.local.revokeToken(label)) throw new BridgeError('not_found', 'no such agent token', 404);
  }

  listTokens(): Array<{ agent_label: string; topic_scope: '*' | string[]; revoked: boolean }> {
    return this.local.tokens().map((token) => ({
      agent_label: token.label,
      topic_scope: token.topics,
      revoked: token.revokedAt !== null,
    }));
  }

  async syncAll(): Promise<{ topics_synced: number; new_messages: number }> {
    await this.#topUp();
    await this.#retryInvites();
    await this.#refreshContacts();
    const welcomes = await this.#takeWelcomes();
    let messages = welcomes;
    for (const topicId of [...this.#sessions.keys()]) {
      messages += await this.#withTopic(topicId, () => this.#syncTopic(topicId));
    }
    return { topics_synced: this.#sessions.size, new_messages: messages };
  }

  /** Agent sync. A topic id outside the token is an error and does not report other topics. */
  async sync(agent: AgentCaller, topicId?: string): Promise<{ topics_synced: number; new_messages: number }> {
    if (topicId !== undefined) {
      this.#requireScope(agent, topicId);
      await this.#topUp();
      await this.#retryInvites();
      const messages = await this.#withTopic(topicId, () => this.#syncTopic(topicId));
      return { topics_synced: 1, new_messages: messages };
    }
    if (agent.topics === '*') return this.syncAll();
    await this.#topUp();
    await this.#retryInvites();
    let messages = 0;
    let topics = 0;
    for (const id of agent.topics) {
      if (!this.#sessions.has(id)) continue;
      messages += await this.#withTopic(id, () => this.#syncTopic(id));
      topics += 1;
    }
    return { topics_synced: topics, new_messages: messages };
  }

  /**
   * Stage an application draft and discard it. The 33rd discard in one epoch
   * throws `self_update_required` and leaves the draft staged. Not an agent tool.
   */
  async discardDraft(topicId: string): Promise<void> {
    const session = this.#requireActive(topicId);
    try {
      await this.#withTopic(topicId, async () => {
        if (!session.staged()) await session.stageMessage({ type: 'update', body: 'discarded draft' });
        await session.abortStaged();
      });
    } catch (err) {
      throw toSurfaceError(err);
    }
  }

  async listTopics(agent: AgentCaller, includeClosed: boolean): Promise<{ topics: Array<Record<string, unknown>> }> {
    const topics = [];
    for (const [topicId, session] of this.#sessions) {
      if (!inScope(agent, topicId)) continue;
      if (session.status === 'pending_join' || session.status === 'left') continue;
      if (session.status === 'closed' && !includeClosed) continue;
      const state = this.local.state(topicId);
      const meta = metaOf(state?.doc);
      topics.push({
        topic_id: topicId,
        slug: meta.slug,
        title: meta.title,
        role: session.role,
        status: session.status,
        state_version: state?.version ?? 0,
        unread_count: this.local.unread(agent.label, topicId),
        last_activity_at: this.local.latestActivity(topicId) ?? new Date(0).toISOString(),
      });
    }
    return { topics };
  }

  async createTopic(
    agent: AgentCaller,
    input: { slug: string; title?: string; initial?: Record<string, unknown> },
  ): Promise<{ topic_id: string; slug: string; state_version: number }> {
    if (input.slug.length < 1 || input.slug.length > 80) throw new BridgeError('invalid_request', 'slug length must be 1..80');
    const topicId = randomUUID();
    const session = await TopicSession.create({
      store: this.mls,
      engine: this.engine,
      topicId,
      credential: this.credential,
    });
    this.#bind(session);
    this.#owners.set(topicId, this.credential.handle);
    await this.relay.createTopic(topicId);
    const title = input.title ?? input.slug;
    const doc = { ...(input.initial ?? {}), _meta: { slug: input.slug, title } };
    await this.#sendApplication(session, {
      type: 'state_snapshot',
      authorAgent: agent.label,
      payload: { version: 0, hash: hashLabel(hashBytes(doc)), doc, reason: 'join' },
    });
    this.local.grantTopic(agent.label, topicId);
    this.#rememberCommit(topicId, Date.now());
    this.#noteMembers(session);
    return { topic_id: topicId, slug: input.slug, state_version: this.local.state(topicId)?.version ?? 0 };
  }

  async listMembers(agent: AgentCaller, topicId: string): Promise<{ members: Array<Record<string, unknown>> }> {
    this.#requireScope(agent, topicId);
    const session = this.#session(topicId);
    this.#noteMembers(session);
    return {
      members: this.local.members(topicId).map((member) => {
        const contact = this.#contactView(member.handle);
        const self = member.handle === this.credential.handle;
        return {
          handle: member.handle,
          role: member.role,
          fingerprint: contact?.fingerprint ?? (self ? this.fingerprint() : ''),
          verified: self ? !contact?.key_changed : (contact?.verified ?? false),
          key_changed: contact?.key_changed ?? false,
          joined_at: member.joinedAt,
          removed_at: member.removedAt,
        };
      }),
    };
  }

  async inviteMember(
    agent: AgentCaller,
    topicId: string,
    handle: string,
  ): Promise<{ status: string; approval_id?: string }> {
    this.#requireScope(agent, topicId);
    const session = this.#requireActive(topicId);
    if (session.role === 'owner') {
      await this.#observeHandle(handle);
      const approvalId = newApprovalId();
      this.local.saveApproval({
        approvalId,
        topicId,
        kind: 'invite',
        requestedBy: `${this.credential.handle}/${agent.label}`,
        summary: `Invite ${handle}`,
        request: { handle },
      });
      return { status: 'pending_approval', approval_id: approvalId };
    }
    await this.#sendApplication(session, {
      type: 'invite_proposal',
      authorAgent: agent.label,
      body: `Invite ${handle}`,
      payload: { handle },
    });
    return { status: 'proposed_to_topic_owner' };
  }

  async removeMember(
    agent: AgentCaller,
    topicId: string,
    handle: string,
    reason: string,
  ): Promise<{ status: string; approval_id?: string }> {
    this.#requireScope(agent, topicId);
    const session = this.#requireActive(topicId);
    if (session.role === 'owner') {
      const approvalId = newApprovalId();
      this.local.saveApproval({
        approvalId,
        topicId,
        kind: 'remove',
        requestedBy: `${this.credential.handle}/${agent.label}`,
        summary: `Remove ${handle}`,
        request: { handle, reason },
      });
      return { status: 'pending_approval', approval_id: approvalId };
    }
    await this.#sendApplication(session, {
      type: 'removal_proposal',
      authorAgent: agent.label,
      body: reason,
      payload: { handle, reason },
    });
    return { status: 'proposed_to_topic_owner' };
  }

  async readMessages(
    agent: AgentCaller,
    input: { topicId: string; sinceSeq?: number; limit?: number; types?: string[] },
  ): Promise<{ messages: Array<Record<string, unknown>>; next_seq: number }> {
    this.#requireScope(agent, input.topicId);
    this.#session(input.topicId);
    const limit = input.limit ?? 50;
    if (limit < 1 || limit > 100) throw new BridgeError('invalid_request', 'limit must be 1..100');
    const after = input.sinceSeq ?? this.local.cursor(agent.label, input.topicId);
    const rows = this.local.envelopes(input.topicId, after, limit);
    const messages = [];
    let cursor = after;
    for (const row of rows) {
      const shown = visibleMessage(row);
      if (!shown) {
        // A stale patch is not shown and does not block later messages.
        cursor = row.seq;
        continue;
      }
      if (input.types !== undefined && !input.types.includes(String(shown.type))) break;
      messages.push(shown);
      cursor = row.seq;
      if (messages.length === limit) break;
    }
    if (input.sinceSeq === undefined && cursor !== after) this.local.advanceCursor(agent.label, input.topicId, cursor);
    return { messages, next_seq: cursor };
  }

  async postMessage(
    agent: AgentCaller,
    input: {
      topicId: string;
      type: 'update' | 'question' | 'request' | 'answer';
      body: string;
      payload?: Record<string, unknown>;
      replyTo?: string;
      requiresApproval?: boolean;
    },
  ): Promise<{ status: string; message_id: string; seq?: number; approval_id?: string }> {
    this.#requireScope(agent, input.topicId);
    const session = this.#requireActive(input.topicId);
    const payload = input.payload ?? {};
    const messageId = newMessageId();
    if (requestNeedsApproval(loadPolicy(this.paths.policy), payload, input.requiresApproval === true)) {
      const approvalId = newApprovalId();
      this.local.saveApproval({
        approvalId,
        topicId: input.topicId,
        kind: 'request',
        requestedBy: `${this.credential.handle}/${agent.label}`,
        summary: input.body.slice(0, 200),
        request: { messageId, type: input.type, body: input.body, payload, replyTo: input.replyTo ?? null, authorAgent: agent.label },
      });
      return { status: 'pending_approval', message_id: messageId, approval_id: approvalId };
    }
    const seq = await this.#sendApplication(session, {
      id: messageId,
      type: input.type,
      body: input.body,
      payload,
      replyTo: input.replyTo ?? null,
      authorAgent: agent.label,
    });
    return { status: 'posted', message_id: messageId, seq };
  }

  async getState(
    agent: AgentCaller,
    topicId: string,
    path?: string,
  ): Promise<{ topic_id: string; version: number; hash: string; doc: unknown; updated_at: string }> {
    this.#requireScope(agent, topicId);
    this.#session(topicId);
    const state = this.local.state(topicId) ?? { version: 0, hash: hashBytes({}), doc: {}, updatedSeq: 0 };
    let doc = state.doc;
    if (path !== undefined && path !== '') {
      const found = pointerValue(doc, path);
      if (!found.ok) throw new BridgeError('invalid_request', found.message);
      doc = found.value;
    }
    return {
      topic_id: topicId,
      version: state.version,
      hash: hashLabel(state.hash),
      doc,
      updated_at: this.local.latestActivity(topicId) ?? new Date(0).toISOString(),
    };
  }

  async proposeState(
    agent: AgentCaller,
    input: { topicId: string; baseVersion: number; patch: PatchOp[]; summary: string; requiresApproval?: boolean },
  ): Promise<{ status: string; new_version?: number; approval_id?: string; current_version?: number }> {
    this.#requireScope(agent, input.topicId);
    const session = this.#requireActive(input.topicId);
    const state = this.local.state(input.topicId);
    const version = state?.version ?? 0;
    if (!state || version !== input.baseVersion) return { status: 'conflict', current_version: version };
    const trial = applyPatch(state.doc, input.patch);
    if (!trial.ok) throw new BridgeError('invalid_patch', trial.message);
    if (patchNeedsApproval(loadPolicy(this.paths.policy), input.patch, input.requiresApproval === true)) {
      const approvalId = newApprovalId();
      this.local.saveApproval({
        approvalId,
        topicId: input.topicId,
        kind: 'state_change',
        requestedBy: `${this.credential.handle}/${agent.label}`,
        summary: input.summary,
        request: { baseVersion: input.baseVersion, patch: input.patch, summary: input.summary, authorAgent: agent.label },
      });
      return { status: 'pending_approval', approval_id: approvalId };
    }
    return this.#publishPatch(session, agent.label, state.doc, state.version, state.hash, input.patch, input.summary, null);
  }

  async listApprovals(
    agent: AgentCaller,
    input: { topicId?: string; status?: string },
  ): Promise<{ items: Array<Record<string, unknown>> }> {
    const status = input.status ?? 'pending';
    const items = this.local.approvals(agent.topics, status).filter((row) => {
      if (input.topicId && row.topicId !== input.topicId) return false;
      return inScope(agent, row.topicId);
    });
    return { items: items.map(approvalView) };
  }

  async approve(approvalId: string, passphrase: string): Promise<{ status: string; seq?: number; new_version?: number; current_version?: number }> {
    const row = this.#pendingApproval(approvalId);
    const key = this.#openIdentity(passphrase);
    try {
      if (row.kind === 'join') {
        await this.#session(row.topicId).acceptJoin();
        this.#rememberCommit(row.topicId, Date.now());
        this.local.decideApproval(approvalId, 'done');
        return { status: 'approved' };
      }
      if (row.kind === 'invite') {
        await this.#requireTrustedContact((row.request as { handle?: string }).handle ?? '');
        const seq = await this.#commitInvite(row, key);
        if (seq < 0) return { status: 'pending' };
        this.local.decideApproval(approvalId, 'done');
        return { status: 'approved', seq };
      }
      if (row.kind === 'remove') {
        const seq = await this.#commitRemove(row, key);
        this.local.decideApproval(approvalId, 'done');
        return { status: 'approved', seq };
      }
      if (row.kind === 'request') {
        const seq = await this.#postSignedRequest(row, key);
        this.local.decideApproval(approvalId, 'done');
        return { status: 'approved', seq };
      }
      if (row.kind === 'state_change') {
        const result = await this.#postSignedState(row, key);
        this.local.decideApproval(approvalId, result.status === 'conflict' ? 'done' : 'done');
        return result;
      }
      throw new BridgeError('invalid_request', 'unknown approval kind');
    } finally {
      key.fill(0);
    }
  }

  /** Unwraps the identity key and zeroes it. Human routes use this to prove the passphrase. */
  provePassphrase(passphrase: string): void {
    const key = this.#openIdentity(passphrase);
    key.fill(0);
  }

  async reject(approvalId: string, passphrase: string): Promise<void> {
    this.#pendingApproval(approvalId);
    const key = this.#openIdentity(passphrase);
    key.fill(0);
    this.local.decideApproval(approvalId, 'rejected');
  }

  /** Human command. The topic owner's bridge commits the Remove when it sees the leave. */
  async leaveTopic(topicId: string, passphrase: string): Promise<number> {
    this.provePassphrase(passphrase);
    const session = this.#requireActive(topicId);
    if (session.role === 'owner') throw new BridgeError('invalid_request', 'the topic owner closes a topic instead of leaving');
    return this.#sendApplication(session, { type: 'leave' });
  }

  async closeTopic(topicId: string, passphrase: string): Promise<void> {
    this.provePassphrase(passphrase);
    const session = this.#session(topicId);
    if (session.role !== 'owner') throw new BridgeError('unauthorized', 'only the topic owner can close a topic', 403);
    await this.relay.closeTopic(topicId);
    if (session.status === 'active' || session.status === 'stale') {
      this.mls.setStatus(topicId, session.status, 'closed');
      session.status = 'closed';
    }
  }

  /** Publish an empty commit so both ratchets start a new epoch. */
  async selfUpdate(topicId: string): Promise<number> {
    const session = this.#requireActive(topicId);
    return this.#sendCommit(session, {});
  }

  /**
   * Commit a self-Update in every active topic this bridge has not committed
   * in for 7 days. A missing clock (an upgrade, or a lost row) is due: waiting
   * another week would skip the rotation. The clock is the stored commit time,
   * so a restart does not postpone it.
   */
  async runDueSelfUpdates(now = Date.now()): Promise<string[]> {
    const updated: string[] = [];
    for (const [topicId, session] of this.#sessions) {
      if (session.status !== 'active') continue;
      const last = this.#clampCommitClock(topicId, this.local.lastCommitAt(topicId), now);
      if (last !== undefined && now - last < SELF_UPDATE_INTERVAL_MS) continue;
      try {
        await this.selfUpdate(topicId);
        this.#rememberCommit(topicId, now);
        updated.push(topicId);
      } catch {
        // Leave the clock unchanged so the next deadline still fires.
      }
    }
    this.#armSelfUpdateTimer();
    return updated;
  }

  /** Next time a self-update is due, or undefined when nothing is scheduled. */
  nextSelfUpdateAt(): number | undefined {
    return this.#nextSelfUpdateAt;
  }

  /** Read the commit clock and arm a timer for the soonest deadline. */
  rescheduleSelfUpdates(): number | undefined {
    this.#armSelfUpdateTimer();
    return this.#nextSelfUpdateAt;
  }

  /** Sleep actually passed to the timer. Capped; not the full time until the deadline. */
  selfUpdateWakeDelay(): number | undefined {
    return this.#wakeDelayMs;
  }

  listContacts(): ContactView[] {
    return this.local
      .contacts()
      .filter((contact) => contact.handle !== this.credential.handle)
      .map((contact) => this.#viewContact(contact))
      .filter((contact): contact is ContactView => contact !== undefined);
  }

  contact(handle: string): ContactView | undefined {
    return this.#contactView(handle);
  }

  /**
   * Pin on first sight. A different key is recorded and not adopted.
   * Returns the contact as it stands after this observation.
   */
  observeContact(handle: string, observed: Uint8Array): ContactView {
    if (handle === this.credential.handle) {
      const ours = this.credential.identityKey;
      if (!this.mls.pins.has(handle)) this.mls.pinIdentity({ handle, identityKey: ours });
      if (bytesEqual(observed, ours)) this.local.clearPending(handle);
      else this.local.noteKeyChange(handle, observed);
      return this.#contactView(handle) ?? this.#selfView();
    }
    const pinned = this.mls.pins.get(handle);
    if (!pinned) {
      this.mls.pinIdentity({ handle, identityKey: observed });
      return this.#contactView(handle) ?? this.#selfView();
    }
    if (bytesEqual(pinned, observed)) this.local.clearPending(handle);
    else this.local.noteKeyChange(handle, observed);
    const view = this.#contactView(handle);
    if (!view) throw new BridgeError('mls_error', 'contact pin was not stored', 500);
    return view;
  }

  /** Human command. The passphrase proves the person; the fingerprint is the out-of-band check. */
  verifyContact(handle: string, presented: string, passphrase: string): ContactView {
    this.provePassphrase(passphrase);
    const digits = parseFingerprint(presented);
    if (!digits) {
      throw new BridgeError('invalid_request', 'fingerprint must be 60 digits or an agbfp:v1 QR payload');
    }
    const record = this.local.contact(handle);
    if (!record) throw new BridgeError('not_found', 'no such contact', 404);
    const pinnedDigits = fingerprintDigits(record.identityKey);
    const pendingDigits = record.pendingKey ? fingerprintDigits(record.pendingKey) : undefined;
    if (handle === this.credential.handle && digits !== fingerprintDigits(this.credential.identityKey)) {
      throw new BridgeError('invalid_request', 'this bridge will not replace its own identity key');
    }
    if (pendingDigits && digits === pendingDigits && record.pendingKey) {
      // The leaf credential in an existing group still carries the pinned key.
      // Replacing the pin now would make the next message from that member fail
      // credential checks. They have to be removed, then added with the new key.
      if (this.#memberOfTopic(handle)) {
        throw new BridgeError('contact_key_changed', keyChangeRecovery(handle, true), 409, {
          handle,
          recovery: 'remove_then_readd',
        });
      }
      this.mls.rePin(handle, record.pendingKey);
      this.local.clearPending(handle);
      this.local.markVerified(handle);
      const view = this.#contactView(handle);
      if (!view) throw new BridgeError('mls_error', 'contact pin was not stored', 500);
      return view;
    }
    if (digits === pinnedDigits) {
      this.local.markVerified(handle);
      const view = this.#contactView(handle);
      if (!view) throw new BridgeError('mls_error', 'contact pin was not stored', 500);
      return view;
    }
    throw new BridgeError('invalid_request', 'fingerprint does not match the pinned key or the pending key');
  }

  async approvalDetail(agent: AgentCaller, approvalId: string): Promise<Record<string, unknown>> {
    const row = this.local.approval(approvalId);
    if (!row) throw new BridgeError('not_found', 'no such approval', 404);
    if (!inScope(agent, row.topicId)) throw new BridgeError('out_of_scope', 'this agent cannot use that topic', 403);
    return this.#approvalDetail(row);
  }

  /** Every approval, for the local page. Not scoped to an agent token. */
  async humanApproval(approvalId: string): Promise<Record<string, unknown>> {
    const row = this.local.approval(approvalId);
    if (!row) throw new BridgeError('not_found', 'no such approval', 404);
    return this.#approvalDetail(row);
  }

  humanApprovals(status = 'pending'): Array<Record<string, unknown>> {
    return this.local.approvals('*', status).map((row) => approvalView(row));
  }

  async #publishPatch(
    session: Session,
    agentLabel: string | undefined,
    doc: unknown,
    version: number,
    hash: Uint8Array,
    patch: PatchOp[],
    summary: string,
    approval: { sig: string } | null,
  ): Promise<{ status: string; new_version?: number; current_version?: number }> {
    const expected = applyPatch(doc, patch);
    if (!expected.ok) throw new BridgeError('invalid_patch', expected.message);
    const expectedHash = hashBytes(expected.doc);
    await this.#sendApplication(session, {
      type: 'state_patch',
      ...(agentLabel ? { authorAgent: agentLabel } : {}),
      ...(approval ? { approval } : {}),
      payload: { base_version: version, base_hash: hashLabel(hash), patch, summary },
    });
    const after = this.local.state(session.topicId);
    if (after && after.version === version + 1 && bytesEqual(after.hash, expectedHash)) {
      return { status: 'applied', new_version: after.version };
    }
    return { status: 'conflict', current_version: after?.version ?? version };
  }

  async #postSignedRequest(row: ApprovalRow, key: Uint8Array): Promise<number> {
    const request = row.request as {
      messageId: string;
      type: 'update' | 'question' | 'request' | 'answer';
      body: string;
      payload: Record<string, unknown>;
      replyTo: string | null;
      authorAgent?: string;
    };
    const session = this.#requireActive(row.topicId);
    const ts = new Date().toISOString();
    const envelope = {
      v: 1 as const,
      id: request.messageId,
      type: request.type,
      ts,
      author: request.authorAgent
        ? { handle: this.credential.handle, agent: request.authorAgent }
        : { handle: this.credential.handle },
      reply_to: request.replyTo,
      body: request.body,
      payload: request.payload,
      approval: null,
    };
    const sig = signRequest(key, row.topicId, envelope);
    return this.#sendApplication(session, {
      id: request.messageId,
      type: request.type,
      ts,
      body: request.body,
      payload: request.payload,
      replyTo: request.replyTo,
      ...(request.authorAgent ? { authorAgent: request.authorAgent } : {}),
      approval: { sig: Buffer.from(sig).toString('base64') },
    });
  }

  async #postSignedState(row: ApprovalRow, key: Uint8Array): Promise<{ status: string; new_version?: number; current_version?: number }> {
    const request = row.request as { baseVersion: number; patch: PatchOp[]; summary: string; authorAgent?: string };
    const session = this.#requireActive(row.topicId);
    const state = this.local.state(row.topicId);
    if (!state || state.version !== request.baseVersion) {
      return { status: 'conflict', current_version: state?.version ?? 0 };
    }
    const sig = signState(key, row.topicId, state.version, state.hash, request.patch);
    return this.#publishPatch(
      session,
      request.authorAgent,
      state.doc,
      state.version,
      state.hash,
      request.patch,
      request.summary,
      { sig: Buffer.from(sig).toString('base64') },
    );
  }

  async #commitInvite(row: ApprovalRow, key: Uint8Array): Promise<number> {
    const handle = (row.request as { handle: string }).handle;
    const session = this.#requireActive(row.topicId);
    const account = await this.relay.account(handle);
    const device = account.devices.find((candidate) => !candidate.revoked);
    if (!device) throw new BridgeError('not_found', 'that person has no device', 404);
    const certified = verifyDeviceCert(device.cert, account.identityKey);
    if (!certified || certified.deviceId !== device.deviceId || !bytesEqual(certified.signatureKey, device.signatureKey)) {
      throw new BridgeError('mls_error', 'device certificate does not match the account', 500);
    }
    const expiresAt = Math.floor(Date.now() / 1000) + INVITE_CLAIM_SECONDS;
    const signature = signWithLabel(
      key,
      SignatureLabel.add,
      addApprovalContent({
        topicId: row.topicId,
        approvalId: row.approvalId,
        inviteeIdentityKey: account.identityKey,
        inviteeDeviceKey: device.signatureKey,
        role: 'member',
        expiresAt,
      }),
    );
    let keyPackage: Uint8Array;
    try {
      keyPackage = await this.relay.claim(device.deviceId, {
        topicId: row.topicId,
        approvalId: row.approvalId,
        expiresAt,
        approval: signature,
      });
    } catch (err) {
      if (err instanceof BridgeError && err.details.relay_error === 'no_key_package') {
        // Stay pending. sync retries the stored signature until expiresAt. No second approve.
        this.local.updateRequest(row.approvalId, {
          ...(row.request as Record<string, unknown>),
          awaitingKeyPackage: true,
          signature: Buffer.from(signature).toString('base64'),
          expiresAt,
          deviceId: device.deviceId,
        });
        return -1;
      }
      throw err;
    }
    const seq = await this.#sendCommit(session, {
      adds: [{ keyPackage, approvalId: row.approvalId, expiresAt, signature }],
    });
    await this.#sendSnapshot(session, 'join');
    return seq;
  }

  async #commitRemove(row: ApprovalRow, key: Uint8Array): Promise<number> {
    const handle = (row.request as { handle: string }).handle;
    const session = this.#requireActive(row.topicId);
    const member = session.members().find((candidate) => candidate.credential.handle === handle);
    if (!member) throw new BridgeError('not_found', 'that person is not a member', 404);
    const signature = signWithLabel(
      key,
      SignatureLabel.remove,
      removeApprovalContent({ topicId: row.topicId, approvalId: row.approvalId, removedDeviceKey: member.signatureKey }),
    );
    return this.#sendCommit(session, {
      removes: [{ leafIndex: member.leafIndex, approvalId: row.approvalId, signature }],
    });
  }

  async #sendSnapshot(session: Session, reason: string): Promise<void> {
    const state = this.local.state(session.topicId);
    if (!state) return;
    await this.#sendApplication(session, {
      type: 'state_snapshot',
      payload: { version: state.version, hash: hashLabel(state.hash), doc: state.doc, reason },
    });
  }

  async #sendApplication(session: Session, input: Parameters<Session['stageMessage']>[0]): Promise<number> {
    try {
      return await this.#withTopic(session.topicId, async () => {
        if (session.unpublishedApplication >= UNPUBLISHED_GENERATION_SKIP) await this.#sendCommit(session, {});
        for (let attempt = 0; attempt < 5; attempt++) {
          await this.#syncTopic(session.topicId);
          if (session.staged()) await this.#releaseStaged(session);
          const staged = await session.stageMessage(input);
          const posted = await this.relay.post(session.topicId, staged);
          if (posted.ok) {
            await this.#finishPost(session, posted.seq);
            return posted.seq;
          }
          if (posted.code === 'stale_epoch') {
            await this.#syncTopic(session.topicId);
            if (session.staged()) await this.#releaseStaged(session);
            continue;
          }
          if (session.staged()) await this.#releaseStaged(session);
          throw new BridgeError('relay_unavailable', posted.message, 503, { relay_error: posted.code });
        }
        throw new BridgeError('relay_unavailable', 'the relay kept rejecting the epoch', 503);
      });
    } catch (err) {
      throw toSurfaceError(err);
    }
  }

  async #sendCommit(session: Session, input: { adds?: AddRequest[]; removes?: RemoveRequest[] }): Promise<number> {
    try {
      return await this.#withTopic(session.topicId, async () => {
        for (let attempt = 0; attempt < 5; attempt++) {
          await this.#syncTopic(session.topicId);
          if (session.staged()) {
            const postedExisting = await this.#releaseStaged(session);
            if (postedExisting) continue;
          }
          const staged = await session.stageCommit(input);
          const posted = await this.relay.post(session.topicId, staged);
          if (posted.ok) {
            await this.#finishPost(session, posted.seq);
            this.#rememberCommit(session.topicId, Date.now());
            return posted.seq;
          }
          if (posted.code === 'stale_epoch') {
            await this.#syncTopic(session.topicId);
            if (session.staged()) await this.#releaseStaged(session);
            continue;
          }
          if (session.staged()) await this.#releaseStaged(session);
          throw new BridgeError('relay_unavailable', posted.message, 503, { relay_error: posted.code });
        }
        throw new BridgeError('relay_unavailable', 'the relay kept rejecting the epoch', 503);
      });
    } catch (err) {
      throw toSurfaceError(err);
    }
  }

  /**
   * Get a staged draft out of the way. An application draft at the cap is
   * dropped without burning another generation. A commit at the cap is posted,
   * because peers can still decrypt it and aborting is what the cap forbids.
   * Returns true when a commit ciphertext was posted.
   */
  async #releaseStaged(session: Session): Promise<boolean> {
    const staged = session.staged();
    if (!staged) return false;
    const atCap =
      staged.kind === 'application'
        ? session.unpublishedApplication >= UNPUBLISHED_GENERATION_SKIP
        : session.unpublishedHandshake >= UNPUBLISHED_GENERATION_SKIP;
    if (!atCap) {
      await session.abortStaged();
      return false;
    }
    if (staged.kind === 'application') {
      await session.dropStaged();
      return false;
    }
    const posted = await this.relay.post(session.topicId, staged);
    if (!posted.ok) {
      if (posted.code === 'stale_epoch') {
        await this.#syncTopic(session.topicId);
        if (session.staged()) await session.dropStaged();
        return false;
      }
      throw new BridgeError('relay_unavailable', posted.message, 503, { relay_error: posted.code });
    }
    await this.#finishPost(session, posted.seq);
    return true;
  }

  /** Process anything sequenced ahead of our post, then confirm it if the echo has not already. */
  async #finishPost(session: Session, seq: number): Promise<void> {
    await this.#syncTopic(session.topicId);
    if (session.lastSeq < seq) await session.confirmStaged(seq);
    this.#ack(session);
    this.#noteMembers(session);
  }

  async #syncTopic(topicId: string): Promise<number> {
    const session = this.#sessions.get(topicId);
    if (!session || session.status === 'halted') return 0;
    let count = 0;
    for (;;) {
      let page;
      try {
        page = await this.relay.messages(topicId, session.lastSeq);
      } catch (err) {
        if (err instanceof BridgeError && err.details.relay_error === 'member_stale' && session.status === 'active') {
          this.mls.setStatus(topicId, 'active', 'stale');
          session.status = 'stale';
          return count;
        }
        // A removed member can no longer fetch. The Remove commit is delivered inline.
        if (err instanceof BridgeError && err.details.relay_error === 'not_found') return count;
        throw err;
      }
      if (page.length === 0) break;
      for (const message of page) {
        if (message.seq <= session.lastSeq) continue;
        const result = await session.receive(message.seq, message.bytes);
        count += 1;
        if (result.kind === 'halted') return count;
        if (result.kind === 'commit' || result.kind === 'echo') this.#noteMembers(session);
        await this.#afterSeq(topicId, message.seq);
      }
    }
    try {
      const view = await this.relay.topic(topicId);
      this.#owners.set(topicId, view.owner);
      if (view.closedAt && (session.status === 'active' || session.status === 'stale')) {
        this.mls.setStatus(topicId, session.status, 'closed');
        session.status = 'closed';
      }
    } catch {
      // Ciphertext already applied. Membership metadata can wait for the next sync.
    }
    this.#ack(session);
    return count;
  }

  async #afterSeq(topicId: string, seq: number): Promise<void> {
    const session = this.#sessions.get(topicId);
    if (!session || session.role !== 'owner' || session.status !== 'active') return;
    const env = this.local.envelopes(topicId, seq - 1, 1).find((row) => row.seq === seq);
    if (!env) return;
    if (env.type === 'state_patch' && env.applied) {
      const state = this.local.state(topicId);
      if (state && state.version > 0 && state.version % SNAPSHOT_EVERY === 0) await this.#sendSnapshot(session, 'periodic');
    }
    if (env.type === 'snapshot_request') await this.#sendSnapshot(session, 'requested');
    if (env.type === 'leave' && env.authorHandle !== this.credential.handle) {
      const member = session.members().find((candidate) => candidate.credential.handle === env.authorHandle);
      if (member) {
        await this.#sendCommit(session, {
          removes: [{ leafIndex: member.leafIndex, approvalId: newApprovalId(), leaveSeq: env.seq }],
        });
      }
    }
    if (env.type === 'invite_proposal' || env.type === 'removal_proposal') {
      const payload = env.payload as { handle?: string; reason?: string };
      if (typeof payload.handle !== 'string') return;
      const kind = env.type === 'invite_proposal' ? 'invite' : 'remove';
      const existing = this.local.approvals('*', 'pending').some((row) => {
        return row.topicId === topicId && row.kind === kind && (row.request as { handle?: string }).handle === payload.handle;
      });
      if (existing) return;
      await this.#observeHandle(payload.handle);
      this.local.saveApproval({
        approvalId: newApprovalId(),
        topicId,
        kind,
        requestedBy: `${env.authorHandle}/${env.authorAgent ?? 'agent'}`,
        summary: kind === 'invite' ? `Invite ${payload.handle}` : `Remove ${payload.handle}`,
        request: { handle: payload.handle, reason: payload.reason ?? '' },
      });
    }
  }

  async #takeWelcomes(): Promise<number> {
    return this.#withTopic('__welcome__', () => this.#takeWelcomesLocked());
  }

  async #takeWelcomesLocked(): Promise<number> {
    const welcomes = await this.relay.inbox();
    let taken = 0;
    for (const welcome of welcomes) {
      if (this.#sessions.has(welcome.topicId)) {
        await this.relay.ackWelcome(welcome.id);
        continue;
      }
      const view = await this.relay.topic(welcome.topicId);
      const owner = view.members.find((member) => member.role === 'owner');
      if (!owner) continue;
      const account = await this.relay.account(owner.handle);
      const session = await TopicSession.join({
        store: this.mls,
        engine: this.engine,
        topicId: welcome.topicId,
        welcome: welcome.welcome,
        credential: this.credential,
        ownerIdentityKey: account.identityKey,
        commitSeq: welcome.commitSeq,
      });
      this.#bind(session);
      this.#owners.set(welcome.topicId, owner.handle);
      this.local.saveApproval({
        approvalId: newApprovalId(),
        topicId: welcome.topicId,
        kind: 'join',
        requestedBy: `${owner.handle}/bridge`,
        summary: `${owner.handle} added you to a topic`,
        request: { owner: owner.handle },
      });
      await this.relay.ackWelcome(welcome.id);
      await this.#syncTopic(welcome.topicId);
      this.#noteMembers(session);
      taken += 1;
    }
    return taken;
  }

  async #retryInvites(): Promise<void> {
    const now = Math.floor(Date.now() / 1000);
    for (const row of this.local.approvals('*', 'pending')) {
      const request = row.request as {
        awaitingKeyPackage?: boolean;
        expiresAt?: number;
        signature?: string;
        deviceId?: string;
      };
      if (!request.awaitingKeyPackage || !request.signature || !request.deviceId || request.expiresAt === undefined) continue;
      if (request.expiresAt <= now) {
        this.local.decideApproval(row.approvalId, 'expired');
        continue;
      }
      const handle = (row.request as { handle?: string }).handle;
      // Any trust-check failure leaves the stored signature unclaimed. A
      // changed key, a missing pin row, or a relay miss must not add anyone.
      if (!handle) continue;
      try {
        await this.#requireTrustedContact(handle);
      } catch {
        continue;
      }
      const signature = new Uint8Array(Buffer.from(request.signature, 'base64'));
      try {
        const keyPackage = await this.relay.claim(request.deviceId, {
          topicId: row.topicId,
          approvalId: row.approvalId,
          expiresAt: request.expiresAt,
          approval: signature,
        });
        const session = this.#sessions.get(row.topicId);
        if (!session || session.status !== 'active') continue;
        await this.#sendCommit(session, {
          adds: [{ keyPackage, approvalId: row.approvalId, expiresAt: request.expiresAt, signature }],
        });
        await this.#sendSnapshot(session, 'join');
        this.local.decideApproval(row.approvalId, 'done');
      } catch (err) {
        const surface = toSurfaceError(err);
        if (surface.details.relay_error === 'no_key_package' || surface.code === 'relay_unavailable') continue;
      }
    }
  }

  async #topUp(): Promise<void> {
    const count = await this.relay.keyPackageCount();
    if (count >= KEY_LOW) return;
    const packs = await replenishKeyPackages(this.engine, this.credential, this.mls, KEY_TARGET - count);
    if (packs.length > 0) await this.relay.uploadKeyPackages(packs);
  }

  async #onRelayMessage(event: { topic_id: string; seq: number; message?: string }): Promise<void> {
    const session = this.#sessions.get(event.topic_id);
    if (!session || session.status === 'halted' || session.status === 'left') return;
    if (event.message && event.seq === session.lastSeq + 1) {
      const bytes = fromBase64(event.message);
      if (bytes) {
        const result = await session.receive(event.seq, bytes);
        if (result.kind === 'halted') return;
        if (result.kind === 'commit' || result.kind === 'echo') this.#noteMembers(session);
        await this.#afterSeq(event.topic_id, event.seq);
        this.#ack(session);
      }
    }
    // receive() may have moved the topic to left or halted. Re-read through a
    // string so the earlier guard does not hide that.
    const status: string = session.status;
    if (status === 'left' || status === 'halted') return;
    await this.#syncTopic(event.topic_id);
  }

  async #connectSocket(): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      const socket = this.relay.connect((event) => {
        if (this.#closed) return;
        if (event.type === 'message') {
          void this.#withTopic(event.topic_id, () => this.#onRelayMessage(event)).catch(() => undefined);
          return;
        }
        if (event.type === 'welcome') {
          void this.#takeWelcomes().catch(() => undefined);
          return;
        }
        if (event.type === 'key_packages_low') void this.#topUp().catch(() => undefined);
      });
      this.#socket = socket;
      socket.once('open', () => resolve());
      socket.once('error', () => reject(new BridgeError('relay_unavailable', 'the relay websocket could not be opened', 503)));
      socket.on('close', () => {
        if (this.#closed || socket !== this.#socket) return;
        setTimeout(() => {
          void this.#reconnect();
        }, 500);
      });
    });
  }

  async #reconnect(): Promise<void> {
    if (this.#closed) return;
    try {
      await this.relay.login();
      await this.#connectSocket();
      await this.syncAll();
    } catch {
      if (!this.#closed) setTimeout(() => void this.#reconnect(), 1000);
    }
  }

  #ack(session: Session): void {
    if (this.#socket) this.relay.sendAck(this.#socket, session.topicId, session.lastSeq);
  }

  #bind(session: Session): void {
    session.onPersisted = (db, frame) => this.local.applyFrame(db, frame);
    this.#sessions.set(session.topicId, session);
  }

  #noteMembers(session: Session): void {
    const now = new Date().toISOString();
    const owner = this.#owners.get(session.topicId);
    const present = new Set<string>();
    for (const member of session.members()) {
      present.add(member.credential.handle);
      const role = member.credential.handle === owner ? 'owner' : 'member';
      this.local.seeMember(session.topicId, member.credential.handle, role, now);
    }
    const gone = this.local
      .members(session.topicId)
      .filter((member) => member.removedAt === null && !present.has(member.handle))
      .map((member) => member.handle);
    if (gone.length > 0) this.local.markRemoved(session.topicId, gone, now);
  }

  #memberOfTopic(handle: string): boolean {
    for (const session of this.#sessions.values()) {
      if (session.status === 'left' || session.status === 'closed') continue;
      if (session.members().some((member) => member.credential.handle === handle)) return true;
    }
    return false;
  }

  #rememberCommit(topicId: string, at: number): void {
    this.local.noteCommit(topicId, at);
    this.#armSelfUpdateTimer();
  }

  /** A commit timestamp ahead of the wall clock is skew. Treat it as now. */
  #clampCommitClock(topicId: string, last: number | undefined, now: number): number | undefined {
    if (last === undefined || last <= now) return last;
    this.local.noteCommit(topicId, now);
    return now;
  }

  /**
   * One timer, aimed at the soonest stored deadline. Overdue topics are not
   * scheduled: startup's runDueSelfUpdates already commits those immediately.
   * setTimeout accepts the 7-day delay (it is under 2^31-1 ms).
   */
  #armSelfUpdateTimer(): void {
    if (this.#selfUpdateTimer) clearTimeout(this.#selfUpdateTimer);
    this.#selfUpdateTimer = undefined;
    this.#nextSelfUpdateAt = undefined;
    this.#wakeDelayMs = undefined;
    if (this.#closed) return;
    let soonest: number | undefined;
    let overdue = false;
    const now = Date.now();
    for (const [topicId, session] of this.#sessions) {
      if (session.status !== 'active') continue;
      const last = this.#clampCommitClock(topicId, this.local.lastCommitAt(topicId), now);
      const dueAt = last === undefined ? now : last + SELF_UPDATE_INTERVAL_MS;
      if (dueAt <= now) {
        // A failed commit leaves the deadline in the past. Try again shortly
        // instead of waiting for the next process start.
        overdue = true;
        continue;
      }
      if (soonest === undefined || dueAt < soonest) soonest = dueAt;
    }
    if (overdue) {
      const retryAt = now + 30_000;
      if (soonest === undefined || retryAt < soonest) soonest = retryAt;
    }
    if (soonest === undefined) return;
    this.#nextSelfUpdateAt = soonest;
    const delay = selfUpdateTimerDelay(soonest, Date.now());
    this.#wakeDelayMs = delay;
    this.#selfUpdateTimer = setTimeout(() => {
      this.#selfUpdateTimer = undefined;
      if (this.#closed) return;
      void this.runDueSelfUpdates().catch(() => this.#armSelfUpdateTimer());
    }, delay);
    this.#selfUpdateTimer.unref();
  }

  async #refreshContacts(): Promise<void> {
    for (const handle of [...this.mls.pins.keys()]) {
      try {
        const account = await this.relay.account(handle);
        this.observeContact(handle, account.identityKey);
      } catch {
        // A relay miss leaves the last observation in place. It does not unpin.
      }
    }
  }

  async #observeHandle(handle: string): Promise<void> {
    try {
      const account = await this.relay.account(handle);
      this.observeContact(handle, account.identityKey);
    } catch {
      // Approve checks again. A missing account does not block creating the request.
    }
  }

  async #requireTrustedContact(handle: string): Promise<ContactView> {
    if (!handle) throw new BridgeError('invalid_request', 'contact handle is required');
    const account = await this.relay.account(handle);
    const view = this.observeContact(handle, account.identityKey);
    if (view.key_changed) {
      const member = this.#memberOfTopic(handle);
      throw new BridgeError('contact_key_changed', keyChangeRecovery(handle, member), 409, {
        handle,
        recovery: member ? 'remove_then_readd' : 'verify',
        pinned_fingerprint: view.fingerprint,
        pending_fingerprint: view.pending_fingerprint,
      });
    }
    return view;
  }

  #contactView(handle: string): ContactView | undefined {
    if (handle === this.credential.handle) {
      const record = this.local.contact(handle);
      if (!record) return this.#selfView();
      return this.#viewContact(record, true);
    }
    const record = this.local.contact(handle);
    return record ? this.#viewContact(record, false) : undefined;
  }

  #viewContact(
    record: { handle: string; identityKey: Uint8Array; verifiedAt: string | null; pendingKey: Uint8Array | null },
    self = false,
  ): ContactView {
    const keyChanged = record.pendingKey !== null;
    return {
      handle: record.handle,
      fingerprint: fingerprint(record.identityKey),
      qr_payload: fingerprintQrPayload(record.identityKey),
      verified: !keyChanged && (self || record.verifiedAt !== null),
      key_changed: keyChanged,
      pending_fingerprint: record.pendingKey ? fingerprint(record.pendingKey) : null,
      pending_qr_payload: record.pendingKey ? fingerprintQrPayload(record.pendingKey) : null,
      verified_at: record.verifiedAt,
    };
  }

  #selfView(): ContactView {
    return {
      handle: this.credential.handle,
      fingerprint: this.fingerprint(),
      qr_payload: fingerprintQrPayload(this.credential.identityKey),
      verified: true,
      key_changed: false,
      pending_fingerprint: null,
      pending_qr_payload: null,
      verified_at: null,
    };
  }

  async #approvalDetail(row: ApprovalRow): Promise<Record<string, unknown>> {
    const state = this.local.state(row.topicId);
    const meta = metaOf(state?.doc);
    const request = isRecord(row.request) ? row.request : {};
    const handle =
      typeof request.handle === 'string' ? request.handle : typeof request.owner === 'string' ? request.owner : undefined;
    let contact: ContactView | undefined;
    if (handle) {
      await this.#observeHandle(handle);
      contact = this.#contactView(handle);
    }
    const policy = loadPolicy(this.paths.policy);
    return {
      ...approvalView(row),
      request,
      topic_title: meta.title,
      topic_slug: meta.slug,
      sensitive_paths: sensitivePaths(row, policy),
      ...(contact ? { contact } : {}),
    };
  }

  #pendingApproval(approvalId: string): ApprovalRow {
    const row = this.local.approval(approvalId);
    if (!row) throw new BridgeError('not_found', 'no such approval', 404);
    if (row.status !== 'pending' && row.status !== 'approved') {
      throw new BridgeError('invalid_request', `approval is ${row.status}`);
    }
    const hours = loadPolicy(this.paths.policy).approval_expiry_hours;
    if (Date.now() - Date.parse(row.createdAt) > hours * 3600 * 1000) {
      this.local.decideApproval(approvalId, 'expired');
      throw new BridgeError('invalid_request', 'approval has expired');
    }
    return row;
  }

  #openIdentity(passphrase: string): Uint8Array {
    const identity = this.local.identity();
    if (!identity) throw new BridgeError('mls_error', 'identity key is missing', 500);
    return unwrapPassphrase(identity.wrappedPrivate, passphrase, utf8(`identity-key:${identity.handle}`));
  }

  #session(topicId: string): Session {
    const session = this.#sessions.get(topicId);
    if (!session) throw new BridgeError('not_found', 'no such topic', 404);
    return session;
  }

  #requireActive(topicId: string): Session {
    const session = this.#session(topicId);
    if (session.status === 'pending_join') {
      throw new BridgeError('topic_pending_join', 'accept the topic before posting', 409);
    }
    if (session.status === 'halted') {
      throw new BridgeError('topic_halted', explain(session.haltReason ?? 'topic is halted'), 409);
    }
    if (session.status !== 'active') throw new BridgeError('topic_halted', 'topic is not active', 409);
    return session;
  }

  #requireScope(agent: AgentCaller, topicId: string): void {
    if (!inScope(agent, topicId)) throw new BridgeError('out_of_scope', 'this agent cannot use that topic', 403);
  }

  async #withTopic<T>(topicId: string, fn: () => Promise<T>): Promise<T> {
    const held = this.#held.getStore();
    if (held?.has(topicId)) return fn();
    const previous = this.#queues.get(topicId) ?? Promise.resolve();
    let release: () => void = () => undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    this.#queues.set(topicId, previous.then(() => gate));
    await previous;
    const next = new Set(held);
    next.add(topicId);
    try {
      return await this.#held.run(next, fn);
    } finally {
      release();
    }
  }
}

function issueToken(local: LocalStore, label: string, topics: '*' | string[]): string {
  const raw = `agb_${randomBytes(32).toString('base64url')}`;
  local.saveToken(sha256(utf8(raw)), label, topics);
  return raw;
}

function inScope(agent: AgentCaller, topicId: string): boolean {
  return agent.topics === '*' || agent.topics.includes(topicId);
}

function visibleMessage(row: EnvelopeRow): Record<string, unknown> | undefined {
  if (row.type === 'state_patch') {
    if (!row.applied) return undefined;
    const payload = row.payload as { summary?: string; base_version?: number };
    const version = typeof payload.base_version === 'number' ? payload.base_version + 1 : undefined;
    return messageView(row, 'system', typeof payload.summary === 'string' ? payload.summary : 'state updated', { version });
  }
  if (row.type === 'leave') return messageView(row, 'system', row.body ?? 'left the topic', row.payload);
  if (row.type === 'invite_proposal' || row.type === 'removal_proposal') {
    const payload = isRecord(row.payload) ? row.payload : {};
    const handle = typeof payload.handle === 'string' ? payload.handle : 'someone';
    const verb = row.type === 'invite_proposal' ? 'Invite' : 'Remove';
    return messageView(row, 'system', row.body ?? `${verb} ${handle}`, payload);
  }
  if (row.type === 'state_snapshot') return messageView(row, 'system', 'state snapshot', row.payload);
  if (!['update', 'question', 'request', 'answer', 'system'].includes(row.type)) return undefined;
  return messageView(row, row.type, row.body ?? undefined, isRecord(row.payload) ? row.payload : {});
}

function messageView(
  row: EnvelopeRow,
  type: string,
  body: string | undefined,
  payload: unknown,
): Record<string, unknown> {
  const author: Record<string, string> = { handle: row.authorHandle };
  if (row.authorAgent) author.agent = row.authorAgent;
  return {
    id: row.messageId,
    seq: row.seq,
    type,
    author,
    ts: row.ts,
    ...(body !== undefined ? { body } : {}),
    payload,
    reply_to: null,
    approval: row.approvalOk ? 'signed' : 'none',
  };
}

function approvalView(row: ApprovalRow): Record<string, unknown> {
  return {
    approval_id: row.approvalId,
    kind: row.kind,
    topic_id: row.topicId,
    status: row.status,
    summary: row.summary,
    requested_by: row.requestedBy,
    created_at: row.createdAt,
    decided_at: row.decidedAt,
    hold: holdKind(row),
  };
}

function keyChangeRecovery(handle: string, stillMember: boolean): string {
  if (stillMember) {
    return `${handle}'s identity key changed while they are still a member. Recovery is remove, then re-add: remove ${handle} from the topic, compare the new fingerprint out of band, run agb contact verify ${handle} <fingerprint>, then invite ${handle} again.`;
  }
  return `${handle}'s identity key changed. Compare the new fingerprint out of band and run agb contact verify ${handle} <fingerprint> before trusting it. An add stays blocked until then.`;
}

function holdKind(row: ApprovalRow): string | null {
  if (row.kind === 'state_change') return 'sensitive_path';
  if (row.kind !== 'request' || !isRecord(row.request)) return null;
  const payload = row.request.payload;
  if (!isRecord(payload) || typeof payload.kind !== 'string') return null;
  if (payload.kind === 'spend' || payload.kind === 'external_message') return payload.kind;
  return null;
}

function sensitivePaths(row: ApprovalRow, policy: ReturnType<typeof loadPolicy>): string[] {
  if (row.kind !== 'state_change' || !isRecord(row.request) || !Array.isArray(row.request.patch)) return [];
  const found: string[] = [];
  for (const op of row.request.patch) {
    if (!isRecord(op)) continue;
    for (const key of ['path', 'from']) {
      const pointer = op[key];
      if (typeof pointer === 'string' && pathIsSensitive(policy, pointer) && !found.includes(pointer)) found.push(pointer);
    }
  }
  return found;
}

function metaOf(doc: unknown): { slug: string; title: string } {
  if (!isRecord(doc) || !isRecord(doc._meta)) return { slug: '', title: '' };
  return {
    slug: typeof doc._meta.slug === 'string' ? doc._meta.slug : '',
    title: typeof doc._meta.title === 'string' ? doc._meta.title : '',
  };
}

function explain(reason: string): string {
  return (
    REASON_TEXT[reason] ??
    (reason === 'state_diverged' ? 'Shared state diverged. This topic is halted.' : reason)
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function sha256(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(createHash('sha256').update(bytes).digest());
}

function newApprovalId(): string {
  return `apr_${randomBytes(8).toString('hex')}`;
}

function newMessageId(): string {
  return `msg_${randomBytes(16).toString('hex')}`;
}

function writeSecret(path: string, bytes: Uint8Array): void {
  writeFileSync(path, bytes, { mode: 0o600 });
  chmodSync(path, 0o600);
}

function exists(path: string): boolean {
  try {
    readFileSync(path);
    return true;
  } catch {
    return false;
  }
}
