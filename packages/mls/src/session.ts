// One topic on one bridge: MLS state plus the rules around it.
//
// Sends persist the post-encrypt state before anything is handed to the relay,
// so a crash cannot reuse a ratchet generation. Inbound messages persist the
// new state, the seq, and the message record in one transaction. A commit that
// fails section 5.8 halts the topic in that same style of transaction and
// leaves the previous MLS state in place; the session then refuses to send.

import { randomBytes } from 'node:crypto';
import {
  bytesEqual,
  decodeMlsMessageHeader,
  encodeBridgeCredential,
  encodeCommitApprovals,
  fromBase64,
  toBase64,
  uuidToBytes,
  validateLeafCredential,
  verifyDeviceCert,
} from '@agent-bridge/protocol';
import type { AddApprovalEntry, RemoveApprovalEntry } from '@agent-bridge/protocol';
import { evaluateCommit } from './commit-policy.ts';
import type { CommitDecision } from './commit-policy.ts';
import { encodeEnvelope, parseEnvelope } from './envelope.ts';
import type { Envelope, MessageType } from './envelope.ts';
import { MlsOperationError } from './errors.ts';
import { readKeyPackage } from './key-package.ts';
import { MlsStore } from './store.ts';
import type { IdentityPin, PendingRow, TopicRole, TopicStatus } from './store.ts';
import type { CommitInspection, Credential, GroupState, Member, MlsEngine, ProcessResult } from './types.ts';

const KEY_PACKAGE_TTL_SECONDS = 30 * 24 * 60 * 60;

export interface OutgoingMessage {
  type: MessageType;
  id?: string;
  body?: string;
  payload?: Record<string, unknown>;
  replyTo?: string | null;
  approval?: { sig: string } | null;
  authorAgent?: string;
}

export interface AddRequest {
  /** MLSMessage KeyPackage, as returned by the relay's claim endpoint. */
  keyPackage: Uint8Array;
  approvalId: string;
  expiresAt: number;
  /** Topic-owner identity signature over the add content (section 8.5). */
  signature: Uint8Array;
}

export interface RemoveRequest {
  leafIndex: number;
  approvalId: string;
  /** Set for an identity-signed removal. Exactly one of signature and leaveSeq. */
  signature?: Uint8Array;
  /** Relay seq of that member's own leave message. */
  leaveSeq?: number;
}

export interface RelayAdd {
  deviceId: string;
  approvalId: string;
  expiresAt: number;
  approval: Uint8Array;
}

export interface RelayRemove {
  deviceId: string;
  approvalId: string;
  approval: Uint8Array | null;
  leaveSeq: number | null;
}

export interface StagedOutbound {
  kind: 'application' | 'commit';
  message: Uint8Array;
  welcome?: Uint8Array;
  epoch: bigint;
  adds: RelayAdd[];
  removes: RelayRemove[];
}

export type ReceiveResult =
  | { kind: 'duplicate' }
  | { kind: 'echo' }
  | { kind: 'halted'; reason: string }
  | { kind: 'application'; sender: Member; envelope: Envelope | null; authorMatches: boolean }
  | { kind: 'commit'; committer: Member; added: Member[]; removed: Member[] };

interface Pending extends StagedOutbound {
  mlsState: Uint8Array;
  envelope?: Envelope;
  approvalIds: string[];
  pins: IdentityPin[];
}

interface Manifest {
  kind: 'application' | 'commit';
  approvalIds: string[];
  pins: Array<{ handle: string; identityKey: string }>;
  adds: Array<{ deviceId: string; approvalId: string; expiresAt: number; approval: string }>;
  removes: Array<{ deviceId: string; approvalId: string; approval: string | null; leaveSeq: number | null }>;
  envelope?: Envelope;
}

export class TopicSession {
  readonly topicId: string;
  readonly engine: MlsEngine;
  readonly store: MlsStore;
  role: TopicRole;
  status: TopicStatus;
  epoch: bigint;
  lastSeq: number;
  haltReason: string | null = null;
  readonly #ourHandle: string;
  readonly #devicePublicKey: Uint8Array;
  readonly #ownerIdentityKey: Uint8Array;
  #confirmed: GroupState;
  #pending: Pending | undefined;
  #queue: Promise<void> = Promise.resolve();

  private constructor(init: {
    store: MlsStore;
    engine: MlsEngine;
    topicId: string;
    role: TopicRole;
    status: TopicStatus;
    epoch: bigint;
    lastSeq: number;
    haltReason: string | null;
    ourHandle: string;
    devicePublicKey: Uint8Array;
    ownerIdentityKey: Uint8Array;
    confirmed: GroupState;
    pending?: Pending;
  }) {
    this.store = init.store;
    this.engine = init.engine;
    this.topicId = init.topicId;
    this.role = init.role;
    this.status = init.status;
    this.epoch = init.epoch;
    this.lastSeq = init.lastSeq;
    this.haltReason = init.haltReason;
    this.#ourHandle = init.ourHandle;
    this.#devicePublicKey = init.devicePublicKey;
    this.#ownerIdentityKey = init.ownerIdentityKey;
    this.#confirmed = init.confirmed;
    this.#pending = init.pending;
  }

  static async create(opts: {
    store: MlsStore;
    engine: MlsEngine;
    topicId: string;
    credential: Credential;
  }): Promise<TopicSession> {
    const devicePublicKey = ownDeviceKey(opts.credential);
    const state = await opts.engine.createGroup(uuidToBytes(opts.topicId), opts.credential);
    opts.store.createTopic(
      {
        topicId: opts.topicId,
        status: 'active',
        role: 'owner',
        ourHandle: opts.credential.handle,
        devicePublicKey,
        ownerIdentityKey: opts.credential.identityKey,
        engineId: opts.engine.id,
        mlsState: opts.engine.serialize(state),
        epoch: opts.engine.epoch(state),
        lastSeq: 0,
      },
      [{ handle: opts.credential.handle, identityKey: opts.credential.identityKey }],
    );
    return TopicSession.open(opts.store, opts.engine, opts.topicId);
  }

  /**
   * Join from a Welcome using one of the KeyPackages this store still holds.
   * The topic starts `pending_join` until `acceptJoin`. `commitSeq` is the
   * relay seq of the add commit; messages at or before it are not fetched.
   */
  static async join(opts: {
    store: MlsStore;
    engine: MlsEngine;
    topicId: string;
    welcome: Uint8Array;
    credential: Credential;
    ownerIdentityKey: Uint8Array;
    commitSeq: number;
  }): Promise<TopicSession> {
    const devicePublicKey = ownDeviceKey(opts.credential);
    const now = Math.floor(Date.now() / 1000);
    let state: GroupState | undefined;
    let usedRef: Uint8Array | undefined;
    let lastError: unknown;
    for (const kp of opts.store.keyPackages(now)) {
      try {
        state = await opts.engine.join(opts.welcome, kp.privatePackage);
        usedRef = kp.ref;
        break;
      } catch (err) {
        lastError = err;
      }
    }
    if (!state || !usedRef) {
      throw lastError instanceof Error ? lastError : new MlsOperationError('mls_error', 'no KeyPackage matched the Welcome');
    }
    const members = opts.engine.members(state);
    if (!members.some((member) => bytesEqual(member.credential.identityKey, opts.ownerIdentityKey))) {
      throw new MlsOperationError('invalid_commit', 'topic owner is not in the joined group');
    }
    if (!members.some((member) => bytesEqual(member.signatureKey, devicePublicKey))) {
      throw new MlsOperationError('mls_error', 'this device is not in the joined group');
    }
    if (!bytesEqual(opts.engine.groupId(state), uuidToBytes(opts.topicId))) {
      throw new MlsOperationError('mls_error', 'Welcome group_id does not match the topic id');
    }
    const pins = members.map((member) => ({ handle: member.credential.handle, identityKey: member.credential.identityKey }));
    opts.store.createTopic(
      {
        topicId: opts.topicId,
        status: 'pending_join',
        role: 'member',
        ourHandle: opts.credential.handle,
        devicePublicKey,
        ownerIdentityKey: opts.ownerIdentityKey,
        engineId: opts.engine.id,
        mlsState: opts.engine.serialize(state),
        epoch: opts.engine.epoch(state),
        lastSeq: opts.commitSeq,
      },
      pins,
      usedRef,
    );
    return TopicSession.open(opts.store, opts.engine, opts.topicId);
  }

  static open(store: MlsStore, engine: MlsEngine, topicId: string): TopicSession {
    const row = store.topic(topicId);
    if (!row) throw new MlsOperationError('not_found', 'no such topic');
    if (row.engineId !== engine.id) {
      throw new MlsOperationError('mls_error', `topic was saved by ${row.engineId}, this engine is ${engine.id}`);
    }
    const confirmed = engine.deserialize(row.mlsState);
    if (row.status !== 'left') {
      const present = engine.members(confirmed).some((member) => bytesEqual(member.signatureKey, row.devicePublicKey));
      if (!present) throw new MlsOperationError('mls_error', 'stored group does not contain this device');
    }
    const pendingRow = store.pending(topicId);
    return new TopicSession({
      store,
      engine,
      topicId,
      role: row.role,
      status: row.status,
      epoch: engine.epoch(confirmed),
      lastSeq: row.lastSeq,
      haltReason: row.haltReason,
      ourHandle: row.ourHandle,
      devicePublicKey: row.devicePublicKey,
      ownerIdentityKey: row.ownerIdentityKey,
      confirmed,
      ...(pendingRow ? { pending: decodePending(engine, pendingRow) } : {}),
    });
  }

  confirmedState(): GroupState {
    return this.#confirmed;
  }

  members(): Member[] {
    return this.engine.members(this.#confirmed);
  }

  staged(): StagedOutbound | undefined {
    return this.#pending ? toPublic(this.#pending) : undefined;
  }

  async acceptJoin(): Promise<void> {
    await this.#exclusive(async () => {
      if (this.status !== 'pending_join') throw new MlsOperationError('mls_error', 'topic is not pending join');
      this.store.setStatus(this.topicId, 'pending_join', 'active');
      this.status = 'active';
    });
  }

  async stageMessage(input: OutgoingMessage): Promise<StagedOutbound> {
    return this.#exclusive(async () => {
      this.#assertCanSend(input.type);
      if (this.#pending) throw new MlsOperationError('outbound_pending', 'confirm or abort the staged message first');
      const me = this.#self();
      const envelope = createEnvelope(me.credential.handle, input);
      const encrypted = await this.engine.encrypt(this.#confirmed, encodeEnvelope(envelope));
      const pending: Pending = {
        kind: 'application',
        message: encrypted.message,
        mlsState: this.engine.serialize(encrypted.next),
        epoch: this.engine.epoch(encrypted.next),
        envelope,
        approvalIds: [],
        pins: [],
        adds: [],
        removes: [],
      };
      this.store.stagePending(this.topicId, encodePending(pending));
      this.#pending = pending;
      return toPublic(pending);
    });
  }

  /** Add, remove, or (with neither) publish a self-Update. */
  async stageCommit(input: { adds?: AddRequest[]; removes?: RemoveRequest[] } = {}): Promise<StagedOutbound> {
    return this.#exclusive(async () => {
      this.#assertCanSend('update');
      if (this.#pending) throw new MlsOperationError('outbound_pending', 'confirm or abort the staged message first');
      const now = Math.floor(Date.now() / 1000);
      const addEntries: AddApprovalEntry[] = [];
      const removeEntries: RemoveApprovalEntry[] = [];
      const proposals: CommitInspection['proposals'] = [];
      const adds: RelayAdd[] = [];
      const removes: RelayRemove[] = [];
      const members = this.members();

      for (const add of input.adds ?? []) {
        if (!Number.isSafeInteger(add.expiresAt) || add.expiresAt <= now) {
          throw new MlsOperationError('invalid_commit', 'approval expired');
        }
        const kp = readKeyPackage(add.keyPackage);
        const leaf = validateLeafCredential(
          encodeBridgeCredential(kp.credential),
          kp.signatureKey,
          this.store.pins.get(kp.credential.handle),
        );
        if (!leaf.ok) throw new MlsOperationError('invalid_commit', leaf.reason);
        addEntries.push({
          approvalId: add.approvalId,
          deviceKey: kp.signatureKey,
          expiresAt: add.expiresAt,
          signature: add.signature,
        });
        proposals.push({ kind: 'add', added: { leafIndex: -1, signatureKey: kp.signatureKey, credential: kp.credential } });
        adds.push({ deviceId: kp.credential.deviceId, approvalId: add.approvalId, expiresAt: add.expiresAt, approval: add.signature });
      }

      for (const remove of input.removes ?? []) {
        const member = members.find((candidate) => candidate.leafIndex === remove.leafIndex);
        if (!member) throw new MlsOperationError('invalid_commit', 'remove does not name a current member');
        const signed = remove.signature !== undefined;
        const cited = remove.leaveSeq !== undefined;
        if (signed === cited) throw new MlsOperationError('invalid_commit', 'a remove needs exactly one of signature or leaveSeq');
        if (remove.signature) {
          removeEntries.push({
            kind: 'remove',
            approvalId: remove.approvalId,
            deviceKey: member.signatureKey,
            signature: remove.signature,
          });
          removes.push({
            deviceId: member.credential.deviceId,
            approvalId: remove.approvalId,
            approval: remove.signature,
            leaveSeq: null,
          });
        } else {
          removeEntries.push({
            kind: 'leave',
            approvalId: remove.approvalId,
            deviceKey: member.signatureKey,
            leaveSeq: remove.leaveSeq!,
          });
          removes.push({
            deviceId: member.credential.deviceId,
            approvalId: remove.approvalId,
            approval: null,
            leaveSeq: remove.leaveSeq!,
          });
        }
        proposals.push({ kind: 'remove', removed: member });
      }

      const authenticatedData =
        proposals.length === 0 ? new Uint8Array() : encodeCommitApprovals({ adds: addEntries, removes: removeEntries });
      const decision = evaluateCommit(
        { committer: this.#self(), proposals, authenticatedData },
        this.#policyContext(),
      );
      if (!decision.ok) throw new MlsOperationError('invalid_commit', decision.reason);

      const committed = await this.engine.commit(this.#confirmed, {
        adds: (input.adds ?? []).map((add) => add.keyPackage),
        removes: (input.removes ?? []).map((remove) => remove.leafIndex),
        authenticatedData,
      });
      if (adds.length > 0 && !committed.welcome) throw new MlsOperationError('mls_error', 'add commit did not produce a Welcome');
      const pending: Pending = {
        kind: 'commit',
        message: committed.commit,
        ...(committed.welcome ? { welcome: committed.welcome } : {}),
        mlsState: this.engine.serialize(committed.pending),
        epoch: this.engine.epoch(committed.pending),
        approvalIds: decision.approvalIds,
        pins: decision.pins,
        adds,
        removes,
      };
      this.store.stagePending(this.topicId, encodePending(pending));
      this.#pending = pending;
      return toPublic(pending);
    });
  }

  async confirmStaged(seq: number): Promise<void> {
    await this.#exclusive(async () => {
      this.#confirm(seq);
    });
  }

  async abortStaged(): Promise<void> {
    await this.#exclusive(async () => {
      if (!this.#pending) return;
      // An application ciphertext already consumed a generation. Dropping it and
      // encrypting again would authenticate a second plaintext with that generation.
      // A commit draws fresh path secrets, so a rejected commit can be discarded.
      if (this.#pending.kind === 'application') {
        throw new MlsOperationError('outbound_pending', 'an application message has already consumed its ratchet generation');
      }
      this.store.clearPending(this.topicId);
      this.#pending = undefined;
    });
  }

  async receive(seq: number, message: Uint8Array): Promise<ReceiveResult> {
    return this.#exclusive(async () => {
      if (this.status === 'halted') return { kind: 'halted', reason: this.haltReason ?? 'topic is halted' };
      if (seq <= this.lastSeq) return { kind: 'duplicate' };
      if (seq !== this.lastSeq + 1) throw new MlsOperationError('seq_gap', `expected seq ${this.lastSeq + 1}, got ${seq}`);
      if (this.status === 'left') throw new MlsOperationError('topic_left', 'this bridge has left the topic');
      if (this.#pending && bytesEqual(this.#pending.message, message)) {
        this.#confirm(seq);
        return { kind: 'echo' };
      }

      let header;
      try {
        header = decodeMlsMessageHeader(message);
      } catch (err) {
        const reason = err instanceof Error ? err.message : 'message could not be decoded';
        this.#halt(seq, reason);
        return { kind: 'halted', reason };
      }
      if (header.wireFormat !== 'private_message') {
        this.#halt(seq, 'not a PrivateMessage');
        return { kind: 'halted', reason: 'not a PrivateMessage' };
      }
      if (!bytesEqual(header.groupId, uuidToBytes(this.topicId))) {
        this.#halt(seq, 'MLS group_id does not match the topic');
        return { kind: 'halted', reason: 'MLS group_id does not match the topic' };
      }

      // Our own application generation is already consumed. Another member's
      // same-epoch application message uses their ratchet, so it is applied on
      // top of the staged state and the original ciphertext stays staged.
      const mergeIntoPending =
        this.#pending?.kind === 'application' && header.contentType === 'application' && header.epoch === this.epoch;
      const base = mergeIntoPending ? this.engine.deserialize(this.#pending!.mlsState) : this.#confirmed;

      let decision: CommitDecision | undefined;
      let result: ProcessResult;
      try {
        result = await this.engine.process(base, message, (commit) => {
          decision = evaluateCommit(commit, this.#policyContext());
          return decision.ok;
        });
      } catch (err) {
        const reason = err instanceof Error ? err.message : 'message could not be processed';
        this.#halt(seq, reason);
        return { kind: 'halted', reason };
      }

      if (result.kind === 'rejected') {
        const reason = decision && !decision.ok ? decision.reason : result.reason;
        this.#halt(seq, reason);
        return { kind: 'halted', reason };
      }

      if (result.kind === 'application') {
        const envelope = parseEnvelope(result.plaintext);
        const authorMatches = envelope !== null && envelope.author.handle === result.sender.credential.handle;
        const record = {
          signatureKey: result.sender.signatureKey,
          type: envelope && authorMatches ? envelope.type : 'invalid',
          authorMatches,
        };
        if (mergeIntoPending && this.#pending) {
          const mlsState = this.engine.serialize(result.next);
          this.store.writeTopic(this.topicId, {
            mlsState,
            epoch: this.epoch,
            lastSeq: seq,
            status: this.status,
            clearPending: false,
            preserveConfirmed: true,
            message: record,
          });
          this.#pending = { ...this.#pending, mlsState, epoch: this.engine.epoch(result.next) };
          this.lastSeq = seq;
          return { kind: 'application', sender: result.sender, envelope: authorMatches ? envelope : null, authorMatches };
        }
        this.store.writeTopic(this.topicId, {
          mlsState: this.engine.serialize(result.next),
          epoch: this.engine.epoch(result.next),
          lastSeq: seq,
          status: this.status,
          clearPending: true,
          message: record,
        });
        this.#adopt(result.next, seq, this.status);
        return { kind: 'application', sender: result.sender, envelope: authorMatches ? envelope : null, authorMatches };
      }

      if (!decision || !decision.ok) throw new MlsOperationError('mls_error', 'commit was applied without a policy decision');
      const removedSelf = result.removed.some((member) => bytesEqual(member.signatureKey, this.#devicePublicKey));
      const status: TopicStatus = removedSelf ? 'left' : this.status;
      this.store.writeTopic(this.topicId, {
        mlsState: this.engine.serialize(result.next),
        epoch: this.engine.epoch(result.next),
        lastSeq: seq,
        status,
        clearPending: true,
        message: { signatureKey: result.committer.signatureKey, type: 'commit', authorMatches: true },
        approvalIds: decision.approvalIds,
        pins: decision.pins,
      });
      this.#adopt(result.next, seq, status);
      return { kind: 'commit', committer: result.committer, added: result.added, removed: result.removed };
    });
  }

  async #exclusive<T>(fn: () => Promise<T>): Promise<T> {
    const previous = this.#queue;
    let release: () => void = () => {};
    this.#queue = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      return await fn();
    } finally {
      release();
    }
  }

  #confirm(seq: number): void {
    const pending = this.#pending;
    if (!pending) throw new MlsOperationError('mls_error', 'no staged outbound');
    if (seq !== this.lastSeq + 1) throw new MlsOperationError('seq_gap', `expected seq ${this.lastSeq + 1}, got ${seq}`);
    const next = this.engine.deserialize(pending.mlsState);
    const envelope = pending.envelope;
    this.store.writeTopic(this.topicId, {
      mlsState: pending.mlsState,
      epoch: this.engine.epoch(next),
      lastSeq: seq,
      status: this.status,
      clearPending: true,
      message: {
        signatureKey: this.#devicePublicKey,
        type: envelope ? envelope.type : 'commit',
        authorMatches: envelope ? envelope.author.handle === this.#ourHandle : true,
      },
      approvalIds: pending.approvalIds,
      pins: pending.pins,
    });
    this.#adopt(next, seq, this.status);
  }

  #halt(seq: number, reason: string): void {
    this.store.halt(this.topicId, seq, reason);
    this.status = 'halted';
    this.haltReason = reason;
    this.#pending = undefined;
  }

  #adopt(state: GroupState, seq: number, status: TopicStatus): void {
    this.#confirmed = state;
    this.epoch = this.engine.epoch(state);
    this.lastSeq = seq;
    this.status = status;
    this.#pending = undefined;
  }

  #assertCanSend(type: MessageType): void {
    if (this.status === 'halted') throw new MlsOperationError('topic_halted', this.haltReason ?? 'topic is halted');
    if (this.status === 'left') throw new MlsOperationError('topic_left', 'this bridge has left the topic');
    if (this.status === 'pending_join' && type !== 'leave') {
      throw new MlsOperationError('topic_pending_join', 'accept the topic before posting');
    }
  }

  #self(): Member {
    const me = this.members().find((member) => bytesEqual(member.signatureKey, this.#devicePublicKey));
    if (!me) throw new MlsOperationError('mls_error', 'this device is not a member');
    if (me.credential.handle !== this.#ourHandle) {
      throw new MlsOperationError('mls_error', 'leaf handle does not match this bridge');
    }
    return me;
  }

  #policyContext() {
    const consumed = new Set(this.store.approvalIds(this.topicId));
    if (this.#pending) for (const id of this.#pending.approvalIds) consumed.add(id);
    return {
      topicId: this.topicId,
      ownerIdentityKey: this.#ownerIdentityKey,
      consumedApprovalIds: consumed,
      messages: new Map(
        this.store.messages(this.topicId).map((message) => [
          message.seq,
          { signatureKey: message.signatureKey, type: message.type, authorMatches: message.authorMatches },
        ]),
      ),
      pinnedIdentity: (handle: string) => this.store.pins.get(handle),
    };
  }
}

/** Generate KeyPackages, store their private halves, and return the public MLSMessages. */
export async function replenishKeyPackages(
  engine: MlsEngine,
  credential: Credential,
  store: MlsStore,
  n: number,
): Promise<Uint8Array[]> {
  const generated = await engine.generateKeyPackages(n, credential);
  const expiresAt = Math.floor(Date.now() / 1000) + KEY_PACKAGE_TTL_SECONDS;
  const publics: Uint8Array[] = [];
  for (const kp of generated) {
    store.saveKeyPackage(kp.ref, kp.privateKeyPackage, expiresAt);
    publics.push(kp.publicKeyPackage);
  }
  return publics;
}

function ownDeviceKey(credential: Credential): Uint8Array {
  const cert = verifyDeviceCert(credential.deviceCert, credential.identityKey);
  if (!cert || cert.handle !== credential.handle || cert.deviceId !== credential.deviceId) {
    throw new MlsOperationError('invalid_credential', 'device certificate does not match this credential');
  }
  return cert.signatureKey;
}

function createEnvelope(handle: string, input: OutgoingMessage): Envelope {
  const envelope: Envelope = {
    v: 1,
    id: input.id ?? `msg_${randomBytes(16).toString('hex')}`,
    type: input.type,
    ts: new Date().toISOString(),
    author: input.authorAgent ? { handle, agent: input.authorAgent } : { handle },
    reply_to: input.replyTo ?? null,
    payload: input.payload ?? {},
    approval: input.approval ?? null,
  };
  if (input.body !== undefined) envelope.body = input.body;
  return envelope;
}

function toPublic(pending: Pending): StagedOutbound {
  return {
    kind: pending.kind,
    message: pending.message,
    ...(pending.welcome ? { welcome: pending.welcome } : {}),
    epoch: pending.epoch,
    adds: pending.adds,
    removes: pending.removes,
  };
}

function encodePending(pending: Pending): PendingRow {
  const manifest: Manifest = {
    kind: pending.kind,
    approvalIds: pending.approvalIds,
    pins: pending.pins.map((pin) => ({ handle: pin.handle, identityKey: toBase64(pin.identityKey) })),
    adds: pending.adds.map((add) => ({ ...add, approval: toBase64(add.approval) })),
    removes: pending.removes.map((remove) => ({
      deviceId: remove.deviceId,
      approvalId: remove.approvalId,
      approval: remove.approval ? toBase64(remove.approval) : null,
      leaveSeq: remove.leaveSeq,
    })),
    ...(pending.envelope ? { envelope: pending.envelope } : {}),
  };
  return {
    message: pending.message,
    welcome: pending.welcome ?? null,
    mlsState: pending.mlsState,
    manifestJson: JSON.stringify(manifest),
  };
}

function decodePending(engine: MlsEngine, row: PendingRow): Pending {
  const manifest = JSON.parse(row.manifestJson) as Manifest;
  const state = engine.deserialize(row.mlsState);
  const envelope = manifest.envelope ? parseEnvelope(encodeEnvelope(manifest.envelope)) ?? undefined : undefined;
  return {
    kind: manifest.kind,
    message: row.message,
    ...(row.welcome ? { welcome: row.welcome } : {}),
    mlsState: row.mlsState,
    epoch: engine.epoch(state),
    approvalIds: manifest.approvalIds,
    pins: manifest.pins.map((pin) => {
      const identityKey = fromBase64(pin.identityKey);
      if (!identityKey) throw new MlsOperationError('mls_error', 'staged pin is not base64');
      return { handle: pin.handle, identityKey };
    }),
    adds: manifest.adds.map((add) => {
      const approval = fromBase64(add.approval);
      if (!approval) throw new MlsOperationError('mls_error', 'staged approval is not base64');
      return { deviceId: add.deviceId, approvalId: add.approvalId, expiresAt: add.expiresAt, approval };
    }),
    removes: manifest.removes.map((remove) => ({
      deviceId: remove.deviceId,
      approvalId: remove.approvalId,
      approval: remove.approval === null ? null : fromBase64(remove.approval),
      leaveSeq: remove.leaveSeq,
    })),
    ...(envelope ? { envelope } : {}),
  };
}
