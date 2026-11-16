// Test harness: a real relay on a random port, backed by a fresh Postgres
// database per test file, plus a `Person` that registers, logs in, and speaks
// real MLS through ts-mls (as a bridge will in milestone 3).

import { randomBytes, randomUUID } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import pg from 'pg';
import WebSocket from 'ws';
import {
  createApplicationMessage,
  createCommit,
  createGroup,
  decodeMlsMessage,
  defaultCapabilities,
  defaultLifetime,
  emptyPskIndex,
  encodeMlsMessage,
  generateKeyPackageWithKey,
  getCiphersuiteFromName,
  getCiphersuiteImpl,
  joinGroup,
  processPrivateMessage,
} from 'ts-mls';
import type { CiphersuiteImpl, ClientState, KeyPackage, PrivateKeyPackage, Proposal } from 'ts-mls';
import {
  addApprovalContent,
  fromBase64,
  generateEd25519KeyPair,
  issueDeviceCert,
  relayAuthContent,
  removeApprovalContent,
  SignatureLabel,
  signWithLabel,
  toBase64,
  utf8,
  uuidToBytes,
} from '@agent-bridge/protocol';
import { buildApp, createPool, defaults, migrate } from '../src/app.ts';
import type { RelayConfig, RelayContext } from '../src/app.ts';

const ADMIN_URL = process.env.TEST_DATABASE_URL ?? 'postgres://agent_bridge:agent_bridge@127.0.0.1:54329/agent_bridge';
export const ORIGIN = 'http://relay.test';

export const impl: CiphersuiteImpl = await getCiphersuiteImpl(
  getCiphersuiteFromName('MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519'),
);

export interface TestRelay {
  baseUrl: string;
  ctx: RelayContext;
  pool: pg.Pool;
  /** Shifts the relay's clock. */
  clock: { offsetMs: number };
  close(): Promise<void>;
}

export async function startRelay(overrides: Partial<RelayConfig> = {}): Promise<TestRelay> {
  const dbName = `ab_test_${randomBytes(6).toString('hex')}`;
  const admin = new pg.Client({ connectionString: ADMIN_URL });
  await admin.connect();
  await admin.query(`CREATE DATABASE ${dbName}`);
  await admin.end();

  const url = new URL(ADMIN_URL);
  url.pathname = `/${dbName}`;
  const pool = createPool(url.toString());
  await migrate(pool);

  const clock = { offsetMs: 0 };
  const config: RelayConfig = {
    ...defaults,
    databaseUrl: url.toString(),
    origin: ORIGIN,
    tokenSecret: utf8('test-secret-test-secret-test-secret!'),
    host: '127.0.0.1',
    port: 0,
    ...overrides,
  };
  const { app, ctx } = await buildApp({
    config,
    pool,
    now: () => new Date(Date.now() + clock.offsetMs),
    logger: process.env.TEST_LOG ? { level: 'error' } : false,
  });
  await app.listen({ host: '127.0.0.1', port: 0 });
  const { port } = app.server.address() as AddressInfo;

  return {
    baseUrl: `http://127.0.0.1:${port}`,
    ctx,
    pool,
    clock,
    async close() {
      await app.close();
      await pool.end();
      const cleanup = new pg.Client({ connectionString: ADMIN_URL });
      await cleanup.connect();
      await cleanup.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`);
      await cleanup.end();
    },
  };
}

export interface Response<T = any> {
  status: number;
  body: T;
}

export async function call<T = any>(
  relay: TestRelay,
  method: string,
  path: string,
  body?: unknown,
  token?: string,
): Promise<Response<T>> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers['content-type'] = 'application/json';
  if (token) headers.authorization = `Bearer ${token}`;
  const res = await fetch(relay.baseUrl + path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : undefined };
}

export interface GeneratedKeyPackage {
  publicPackage: KeyPackage;
  privatePackage: PrivateKeyPackage;
  /** base64 MLSMessage, as uploaded to the relay. */
  encoded: string;
}

export class Person {
  readonly handle: string;
  readonly identity = generateEd25519KeyPair();
  readonly device = generateEd25519KeyPair();
  readonly deviceId = randomUUID();
  readonly relay: TestRelay;
  token = '';
  #keyPackages: GeneratedKeyPackage[] = [];

  constructor(relay: TestRelay, handle: string) {
    this.relay = relay;
    this.handle = handle;
  }

  static async create(relay: TestRelay, handle: string): Promise<Person> {
    const person = new Person(relay, handle);
    const res = await person.register();
    if (res.status !== 201) throw new Error(`register failed: ${JSON.stringify(res.body)}`);
    await person.login();
    return person;
  }

  deviceCert(overrides: { handle?: string; deviceId?: string } = {}): Uint8Array {
    return issueDeviceCert(this.identity.privateKey, {
      handle: overrides.handle ?? this.handle,
      deviceId: overrides.deviceId ?? this.deviceId,
      signatureKey: this.device.publicKey,
      createdAt: Math.floor(Date.now() / 1000),
    });
  }

  register(cert = this.deviceCert()): Promise<Response> {
    return call(this.relay, 'POST', '/v1/accounts', {
      handle: this.handle,
      identity_pubkey: toBase64(this.identity.publicKey),
      device: { id: this.deviceId, signature_pubkey: toBase64(this.device.publicKey), cert: toBase64(cert) },
    });
  }

  async login(): Promise<string> {
    const challenge = await call(this.relay, 'POST', '/v1/auth/challenge', { device_id: this.deviceId });
    const nonce = fromBase64(challenge.body.nonce)!;
    const signature = signWithLabel(this.device.privateKey, SignatureLabel.relayAuth, relayAuthContent(ORIGIN, nonce));
    const res = await call(this.relay, 'POST', '/v1/auth/token', {
      device_id: this.deviceId,
      nonce: challenge.body.nonce,
      signature: toBase64(signature),
    });
    if (res.status !== 200) throw new Error(`login failed: ${JSON.stringify(res.body)}`);
    this.token = res.body.access_token;
    return this.token;
  }

  call<T = any>(method: string, path: string, body?: unknown): Promise<Response<T>> {
    return call<T>(this.relay, method, path, body, this.token);
  }

  /** A KeyPackage whose leaf signature key is this device's key, as the design requires. */
  async newKeyPackage(): Promise<GeneratedKeyPackage> {
    const kp = await generateKeyPackageWithKey(
      { credentialType: 'basic', identity: utf8(`${this.handle}/${this.deviceId}`) },
      defaultCapabilities(),
      defaultLifetime,
      [],
      { signKey: this.device.privateKey, publicKey: this.device.publicKey },
      impl,
    );
    const encoded = toBase64(encodeMlsMessage({ keyPackage: kp.publicPackage, wireformat: 'mls_key_package', version: 'mls10' }));
    const generated = { ...kp, encoded };
    this.#keyPackages.push(generated);
    return generated;
  }

  async uploadKeyPackages(n: number): Promise<Response> {
    const kps = [];
    for (let i = 0; i < n; i++) kps.push((await this.newKeyPackage()).encoded);
    return this.call('POST', '/v1/key-packages', { key_packages: kps });
  }

  /** Creates the MLS group and registers the topic. */
  async createTopic(): Promise<{ topicId: string; group: ClientState }> {
    const topicId = randomUUID();
    const kp = await this.newKeyPackage();
    const group = await createGroup(uuidToBytes(topicId), kp.publicPackage, kp.privatePackage, [], impl);
    const res = await this.call('POST', '/v1/topics', { id: topicId });
    if (res.status !== 201) throw new Error(`create topic failed: ${JSON.stringify(res.body)}`);
    return { topicId, group };
  }

  signAdd(topicId: string, approvalId: string, invitee: Person, expiresAt = nowSeconds() + 3600): string {
    const content = addApprovalContent({
      topicId,
      approvalId,
      inviteeIdentityKey: invitee.identity.publicKey,
      inviteeDeviceKey: invitee.device.publicKey,
      role: 'member',
      expiresAt,
    });
    return toBase64(signWithLabel(this.identity.privateKey, SignatureLabel.add, content));
  }

  signRemove(topicId: string, approvalId: string, removed: Person): string {
    const content = removeApprovalContent({ topicId, approvalId, removedDeviceKey: removed.device.publicKey });
    return toBase64(signWithLabel(this.identity.privateKey, SignatureLabel.remove, content));
  }

  /** Processes a Welcome with whichever of this person's KeyPackages it was built for. */
  async join(welcomeB64: string): Promise<ClientState> {
    const decoded = decodeMlsMessage(fromBase64(welcomeB64)!, 0)![0];
    if (decoded.wireformat !== 'mls_welcome') throw new Error('not a Welcome');
    for (const kp of this.#keyPackages) {
      try {
        return await joinGroup(decoded.welcome, kp.publicPackage, kp.privatePackage, emptyPskIndex, impl);
      } catch {
        // not this KeyPackage
      }
    }
    throw new Error('no KeyPackage matches this Welcome');
  }
}

export function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

// --- MLS message builders ----------------------------------------------------

export async function appMessage(group: ClientState, text: string): Promise<{ group: ClientState; message: string }> {
  const result = await createApplicationMessage(group, utf8(text), impl);
  const message = encodeMlsMessage({ privateMessage: result.privateMessage, wireformat: 'mls_private_message', version: 'mls10' });
  return { group: result.newState, message: toBase64(message) };
}

export async function commit(
  group: ClientState,
  proposals: Proposal[] = [],
): Promise<{ group: ClientState; message: string; welcome?: string }> {
  const result = await createCommit({ state: group, cipherSuite: impl }, { extraProposals: proposals, ratchetTreeExtension: true });
  return {
    group: result.newState,
    message: toBase64(encodeMlsMessage(result.commit)),
    ...(result.welcome
      ? { welcome: toBase64(encodeMlsMessage({ welcome: result.welcome, wireformat: 'mls_welcome', version: 'mls10' })) }
      : {}),
  };
}

export function decodeKeyPackage(encoded: string): KeyPackage {
  const decoded = decodeMlsMessage(fromBase64(encoded)!, 0)![0];
  if (decoded.wireformat !== 'mls_key_package') throw new Error('not a KeyPackage');
  return decoded.keyPackage;
}

/** Decrypts an application message fetched from the relay. */
export async function readApp(group: ClientState, messageB64: string): Promise<{ group: ClientState; text: string }> {
  const decoded = decodeMlsMessage(fromBase64(messageB64)!, 0)![0];
  if (decoded.wireformat !== 'mls_private_message') throw new Error('not a PrivateMessage');
  const result = await processPrivateMessage(group, decoded.privateMessage, emptyPskIndex, impl);
  if (result.kind !== 'applicationMessage') throw new Error('expected an application message');
  return { group: result.newState, text: new TextDecoder().decode(result.message) };
}

/** Applies a commit fetched from the relay. */
export async function applyCommit(group: ClientState, messageB64: string): Promise<ClientState> {
  const decoded = decodeMlsMessage(fromBase64(messageB64)!, 0)![0];
  if (decoded.wireformat !== 'mls_private_message') throw new Error('not a PrivateMessage');
  const result = await processPrivateMessage(group, decoded.privateMessage, emptyPskIndex, impl);
  if (result.kind !== 'newState') throw new Error('expected a commit');
  return result.newState;
}

// --- WebSocket ---------------------------------------------------------------

export interface EventStream {
  socket: WebSocket;
  events: any[];
  /** Resolves with the first event (already received or future) matching `predicate`. */
  next(predicate: (e: any) => boolean, timeoutMs?: number): Promise<any>;
  close(): void;
}

export async function connectEvents(person: Person): Promise<EventStream> {
  const socket = new WebSocket(person.relay.baseUrl.replace('http', 'ws') + '/v1/ws', {
    headers: { authorization: `Bearer ${person.token}` },
  });
  const events: any[] = [];
  const waiters: Array<{ predicate: (e: any) => boolean; resolve: (e: any) => void }> = [];
  socket.on('message', (raw) => {
    const event = JSON.parse(raw.toString());
    events.push(event);
    for (const w of [...waiters]) {
      if (w.predicate(event)) {
        waiters.splice(waiters.indexOf(w), 1);
        w.resolve(event);
      }
    }
  });
  await new Promise<void>((resolve, reject) => {
    socket.once('open', () => resolve());
    socket.once('unexpected-response', (_req, res) => reject(new Error(`websocket rejected: ${res.statusCode}`)));
    socket.once('error', reject);
  });
  return {
    socket,
    events,
    next(predicate, timeoutMs = 3000) {
      const found = events.find(predicate);
      if (found) return Promise.resolve(found);
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('timed out waiting for event')), timeoutMs);
        waiters.push({ predicate, resolve: (e) => (clearTimeout(timer), resolve(e)) });
      });
    },
    close: () => socket.close(),
  };
}
