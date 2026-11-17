// ts-mls 1.6.4 behind MlsEngine.
//
// Library gaps the design's sketch doesn't hit:
//
// - `processPrivateMessage` does not return the sender of an application
//   message. The secret tree is indexed like the ratchet tree, so the even
//   node whose application ratchet advanced is the sender. In-order processing
//   makes that unique.
// - encrypt, commit, and process mutate the ClientState they are given, so
//   each call copies the group first. A caller that discards the result, or
//   crashes before saving it, still has the previous state.
// - The default AuthenticationService accepts every credential. This engine
//   installs one that enforces section 8.2, including the pinned identity key
//   when this bridge has one. ts-mls calls it for new KeyPackages, for the
//   updated leaf of a commit, and for every leaf of a Welcome. Returning false
//   makes ts-mls throw before the commit callback; a thrown commit is a halt,
//   same as a policy rejection (section 5.8).
//
// `joinGroup` needs the public KeyPackage as well as the private keys, so the
// opaque `privateKeyPackage` blob carries both. Callers do not inspect it.

import {
  bytesEqual,
  decodeBridgeCredential,
  decodeMlsMessageHeader,
  ed25519PublicKeyFromSeed,
  encodeBridgeCredential,
  keyPackageRef,
  toBase64,
  TlsReader,
  TlsWriter,
  validateLeafCredential,
} from '@agent-bridge/protocol';
import {
  createApplicationMessage,
  createCommit,
  createGroup,
  decodeGroupState,
  decodeMlsMessage,
  defaultCapabilities,
  emptyPskIndex,
  encodeGroupState,
  encodeMlsMessage,
  generateKeyPackageWithKey,
  getCiphersuiteFromName,
  getCiphersuiteImpl,
  joinGroup,
  processPrivateMessage,
  zeroOutUint8Array,
} from 'ts-mls';
import type { CiphersuiteImpl, ClientState, Credential as MlsCredential, KeyPackage, Proposal, SecretTree } from 'ts-mls';
import { defaultKeyRetentionConfig } from 'ts-mls/keyRetentionConfig.js';
import { defaultClientConfig } from 'ts-mls/clientConfig.js';
import type { ClientConfig } from 'ts-mls/clientConfig.js';
import { decodeKeyPackage, encodeKeyPackage } from 'ts-mls/keyPackage.js';
import { consumeRatchet } from 'ts-mls/secretTree.js';
import { leafToNodeIndex, toLeafIndex } from 'ts-mls/treemath.js';
import type { LeafNode, PrivateKeyPackage } from 'ts-mls';
import { MlsOperationError } from './errors.ts';
import { TS_MLS_ENGINE_ID } from './types.ts';
import type {
  CommitChange,
  CommitInspection,
  Credential,
  GeneratedKeyPackage,
  GroupState,
  Member,
  MlsEngine,
  ProcessResult,
  ProposalSummary,
} from './types.ts';

const KEY_PACKAGE_TTL_SECONDS = 30 * 24 * 60 * 60;
const LIFETIME_SKEW_SECONDS = 60n;
const STATE_VERSION = 1;

/**
 * Unpublished drafts a receiver will skip. Each aborted application message
 * or commit burns one generation the peer never sees. 32 covers a long run of
 * discarded drafts. The sender refuses an abort that would burn one more, and
 * a ciphertext past this cap halts the peer: the relay will not skip that seq.
 * Skipped keys are not kept (`retainKeysForGenerations: 0`), so an unpublished
 * ciphertext cannot be decrypted once the peer has moved past it.
 */
export const UNPUBLISHED_GENERATION_SKIP = 32;

class TsGroup implements GroupState {
  readonly engineId = TS_MLS_ENGINE_ID;
  readonly client: ClientState;

  constructor(client: ClientState) {
    this.client = client;
  }
}

function assertGroup(state: GroupState): TsGroup {
  if (!(state instanceof TsGroup)) throw new MlsOperationError('mls_error', `group state is not ${TS_MLS_ENGINE_ID}`);
  return state;
}

/** Test-only view of the ts-mls state, used to build commits an honest session refuses. */
export function debugClientState(state: GroupState): ClientState {
  return assertGroup(state).client;
}

interface StoredKeyMaterial {
  keyPackage: KeyPackage;
  privateKeys: PrivateKeyPackage;
}

export interface TsMlsEngineOptions {
  /** 32-byte Ed25519 seed. The bridge's device signing key. */
  devicePrivateKey: Uint8Array;
  /**
   * Pinned identity keys, read at validation time. The session mutates this
   * map as it accepts commits; the engine does not copy it.
   */
  pins?: Map<string, Uint8Array>;
}

export function createTsMlsEngine(options: TsMlsEngineOptions): MlsEngine {
  return new TsMlsEngine(options);
}

class TsMlsEngine implements MlsEngine {
  readonly id = TS_MLS_ENGINE_ID;
  readonly #privateKey: Uint8Array;
  readonly #publicKey: Uint8Array;
  readonly #pins: Map<string, Uint8Array> | undefined;
  readonly #config: ClientConfig;
  #suite: Promise<CiphersuiteImpl> | undefined;

  constructor(options: TsMlsEngineOptions) {
    if (options.devicePrivateKey.length !== 32) throw new TypeError('device private key must be a 32-byte seed');
    this.#privateKey = options.devicePrivateKey;
    this.#publicKey = ed25519PublicKeyFromSeed(options.devicePrivateKey);
    this.#pins = options.pins;
    this.#config = {
      ...defaultClientConfig,
      // The relay rejects stale epochs, so old epoch secrets are not kept.
      // retainKeysForEpochs: 0 does not drop them (Array.slice(-0) keeps all).
      // Skipped generations are deleted, but a peer must be able to step over
      // drafts this sender aborted. See UNPUBLISHED_GENERATION_SKIP.
      keyRetentionConfig: {
        ...defaultKeyRetentionConfig,
        retainKeysForGenerations: 0,
        retainKeysForEpochs: 1,
        maximumForwardRatchetSteps: UNPUBLISHED_GENERATION_SKIP,
      },
      authService: {
        async validateCredential(credential, signaturePublicKey) {
          if (credential.credentialType !== 'basic') return false;
          let handle: string;
          try {
            handle = decodeBridgeCredential(credential.identity).handle;
          } catch {
            return false;
          }
          const pinned = options.pins?.get(handle);
          return validateLeafCredential(credential.identity, signaturePublicKey, pinned).ok;
        },
      },
    };
  }

  async generateKeyPackages(n: number, cred: Credential): Promise<GeneratedKeyPackage[]> {
    if (!Number.isInteger(n) || n < 1 || n > 100) throw new MlsOperationError('mls_error', 'key package count must be 1..100');
    this.#assertOwnCredential(cred);
    const impl = await this.#ciphersuite();
    const out: GeneratedKeyPackage[] = [];
    for (let i = 0; i < n; i++) {
      const generated = await this.#generate(cred, impl);
      const encoded = encodeKeyPackage(generated.publicPackage);
      out.push({
        publicKeyPackage: encodeMlsMessage({
          keyPackage: generated.publicPackage,
          wireformat: 'mls_key_package',
          version: 'mls10',
        }),
        ref: keyPackageRef(encoded),
        privateKeyPackage: encodeStored({ keyPackage: generated.publicPackage, privateKeys: generated.privatePackage }),
      });
    }
    return out;
  }

  async createGroup(groupId: Uint8Array, cred: Credential): Promise<GroupState> {
    this.#assertOwnCredential(cred);
    const impl = await this.#ciphersuite();
    const generated = await this.#generate(cred, impl);
    const client = await createGroup(groupId, generated.publicPackage, generated.privatePackage, [], impl, this.#config);
    return new TsGroup(client);
  }

  async join(welcome: Uint8Array, privateKeyPackage: Uint8Array): Promise<GroupState> {
    const decoded = decodeMlsMessage(welcome, 0);
    if (!decoded || decoded[0].wireformat !== 'mls_welcome') throw new MlsOperationError('mls_error', 'not a Welcome');
    const stored = decodeStored(privateKeyPackage);
    const impl = await this.#ciphersuite();
    const client = await joinGroup(decoded[0].welcome, stored.keyPackage, stored.privateKeys, emptyPskIndex, impl, undefined, undefined, this.#config);
    return new TsGroup(client);
  }

  async commit(state: GroupState, change: CommitChange): Promise<{ commit: Uint8Array; welcome?: Uint8Array; pending: GroupState }> {
    // ts-mls mutates the ClientState it is given. Operate on a copy so a caller
    // that discards the result, or crashes before persisting it, still holds
    // the pre-operation state and can retry.
    const impl = await this.#ciphersuite();
    const proposals: Proposal[] = [];
    for (const leafIndex of change.removes ?? []) proposals.push({ proposalType: 'remove', remove: { removed: leafIndex } });
    for (const message of change.adds ?? []) proposals.push({ proposalType: 'add', add: { keyPackage: keyPackageFromMessage(message) } });
    const result = await createCommit(
      { state: this.#clone(state).client, cipherSuite: impl },
      { extraProposals: proposals, ratchetTreeExtension: true, authenticatedData: change.authenticatedData },
    );
    result.consumed.forEach(zeroOutUint8Array);
    const commit = encodeMlsMessage(result.commit);
    const pending = new TsGroup(forgetOldSecrets(result.newState));
    if (!result.welcome) return { commit, pending };
    return {
      commit,
      welcome: encodeMlsMessage({ welcome: result.welcome, wireformat: 'mls_welcome', version: 'mls10' }),
      pending,
    };
  }

  async encrypt(state: GroupState, plaintext: Uint8Array): Promise<{ message: Uint8Array; next: GroupState }> {
    const impl = await this.#ciphersuite();
    const result = await createApplicationMessage(this.#clone(state).client, plaintext, impl);
    result.consumed.forEach(zeroOutUint8Array);
    return {
      message: encodeMlsMessage({ privateMessage: result.privateMessage, wireformat: 'mls_private_message', version: 'mls10' }),
      next: new TsGroup(result.newState),
    };
  }

  async process(state: GroupState, message: Uint8Array, validateCommit: (commit: CommitInspection) => boolean): Promise<ProcessResult> {
    const group = this.#clone(state);
    const header = decodeMlsMessageHeader(message);
    if (header.wireFormat !== 'private_message') throw new MlsOperationError('mls_error', 'not a PrivateMessage');
    const decoded = decodeMlsMessage(message, 0);
    if (!decoded || decoded[0].wireformat !== 'mls_private_message') throw new MlsOperationError('mls_error', 'not a PrivateMessage');

    const beforeMembers = this.members(group);
    const before = ratchetFingerprint(group.client.secretTree);
    let inspection: CommitInspection | undefined;
    let rejectReason = 'commit rejected by policy';
    const impl = await this.#ciphersuite();
    const result = await processPrivateMessage(group.client, decoded[0].privateMessage, emptyPskIndex, impl, (incoming) => {
      if (incoming.kind !== 'commit') {
        rejectReason = 'standalone proposals are not accepted';
        return 'reject';
      }
      if (incoming.senderLeafIndex === undefined) {
        rejectReason = 'commit sender is not a member';
        return 'reject';
      }
      const committer = memberAt(group.client, incoming.senderLeafIndex);
      if (!committer) {
        rejectReason = 'commit sender is not a member';
        return 'reject';
      }
      inspection = {
        committer,
        proposals: incoming.proposals.map((proposal) => summarizeProposal(group.client, proposal.proposal, proposal.senderLeafIndex)),
        authenticatedData: header.authenticatedData,
      };
      if (!validateCommit(inspection)) {
        rejectReason = 'commit rejected by policy';
        return 'reject';
      }
      return 'accept';
    });

    if (result.kind === 'applicationMessage') {
      result.consumed.forEach(zeroOutUint8Array);
      const sender = memberAt(group.client, changedLeaf(before, ratchetFingerprint(result.newState.secretTree)));
      if (!sender) throw new MlsOperationError('mls_error', 'application sender is not a member');
      return { kind: 'application', sender, plaintext: result.message, next: new TsGroup(forgetOldSecrets(result.newState)) };
    }
    if (result.actionTaken === 'reject' || !inspection) return { kind: 'rejected', reason: rejectReason };
    result.consumed.forEach(zeroOutUint8Array);
    const next = new TsGroup(forgetOldSecrets(result.newState));
    const added = inspection.proposals.flatMap((proposal) => (proposal.kind === 'add' && proposal.added ? [proposal.added] : []));
    const removed = inspection.proposals.flatMap((proposal) => (proposal.kind === 'remove' && proposal.removed ? [proposal.removed] : []));
    // The update path is not a proposal. A member can otherwise replace the
    // credential on their own leaf, and an update-only commit would be accepted.
    if (!commitKeepsIdentity(beforeMembers, this.members(next), inspection)) {
      return { kind: 'rejected', reason: 'credential changed' };
    }
    const leafByKey = new Map(this.members(next).map((member) => [toBase64(member.signatureKey), member.leafIndex]));
    for (const member of added) {
      const leafIndex = leafByKey.get(toBase64(member.signatureKey));
      if (leafIndex !== undefined) member.leafIndex = leafIndex;
    }
    return { kind: 'commit', committer: inspection.committer, added, removed, next };
  }

  members(state: GroupState): Member[] {
    const out: Member[] = [];
    assertGroup(state).client.ratchetTree.forEach((node, nodeIndex) => {
      if (nodeIndex % 2 !== 0 || node?.nodeType !== 'leaf') return;
      const member = memberFromLeaf(node.leaf, nodeIndex / 2);
      if (!member) throw new MlsOperationError('mls_error', 'group contains a leaf without a BridgeCredential');
      out.push(member);
    });
    return out;
  }

  epoch(state: GroupState): bigint {
    return assertGroup(state).client.groupContext.epoch;
  }

  groupId(state: GroupState): Uint8Array {
    return assertGroup(state).client.groupContext.groupId.slice();
  }

  serialize(state: GroupState): Uint8Array {
    // Encoding a copy drops epoch history and skipped generations. The live
    // state is left as it is.
    return new TlsWriter().u8(STATE_VERSION).opaque(encodeGroupState(forgetOldSecrets(assertGroup(state).client))).finish();
  }

  async discardHandshakeGeneration(state: GroupState): Promise<GroupState> {
    const group = this.#clone(state);
    const impl = await this.#ciphersuite();
    const nodeIndex = leafToNodeIndex(toLeafIndex(group.client.privatePath.leafIndex));
    const consumed = await consumeRatchet(group.client.secretTree, nodeIndex, 'commit', impl);
    consumed.consumed.forEach(zeroOutUint8Array);
    return new TsGroup(forgetOldSecrets({ ...group.client, secretTree: consumed.newTree }));
  }

  deserialize(bytes: Uint8Array): GroupState {
    const r = new TlsReader(bytes);
    const version = r.u8();
    if (version !== STATE_VERSION) throw new MlsOperationError('mls_error', `unknown group state version ${version}`);
    const raw = r.opaque();
    r.end();
    const decoded = decodeGroupState(raw, 0);
    if (!decoded || decoded[1] !== raw.length) throw new MlsOperationError('mls_error', 'group state is truncated');
    return new TsGroup({ ...decoded[0], clientConfig: this.#config });
  }

  #clone(state: GroupState): TsGroup {
    return assertGroup(this.deserialize(this.serialize(state)));
  }

  async #ciphersuite(): Promise<CiphersuiteImpl> {
    this.#suite ??= getCiphersuiteImpl(getCiphersuiteFromName('MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519'));
    return this.#suite;
  }

  #assertOwnCredential(cred: Credential): void {
    const check = validateLeafCredential(encodeBridgeCredential(cred), this.#publicKey);
    if (!check.ok) throw new MlsOperationError('invalid_credential', check.reason);
    if (!bytesEqual(check.leaf.credential.identityKey, cred.identityKey)) {
      throw new MlsOperationError('invalid_credential', 'credential identity key does not match');
    }
  }

  async #generate(cred: Credential, impl: CiphersuiteImpl) {
    const mlsCredential: MlsCredential = { credentialType: 'basic', identity: encodeBridgeCredential(cred) };
    const now = BigInt(Math.floor(Date.now() / 1000));
    return generateKeyPackageWithKey(
      mlsCredential,
      defaultCapabilities(),
      { notBefore: now - LIFETIME_SKEW_SECONDS, notAfter: now - LIFETIME_SKEW_SECONDS + BigInt(KEY_PACKAGE_TTL_SECONDS) },
      [],
      { signKey: this.#privateKey, publicKey: this.#publicKey },
      impl,
    );
  }
}

function forgetOldSecrets(client: ClientState): ClientState {
  return {
    ...client,
    historicalReceiverData: new Map(),
    secretTree: client.secretTree.map((node) => {
      if (!node) return node;
      return {
        ...node,
        application: { ...node.application, unusedGenerations: {} },
        handshake: { ...node.handshake, unusedGenerations: {} },
      };
    }),
  };
}

function sameIdentity(left: Credential, right: Credential): boolean {
  return left.handle === right.handle && left.deviceId === right.deviceId && bytesEqual(left.identityKey, right.identityKey);
}

/**
 * An update path or Update proposal may rotate HPKE and signature keys.
 * Handle, identity key, and device id must stay the committer's current leaf.
 */
function commitKeepsIdentity(before: Member[], after: Member[], commit: CommitInspection): boolean {
  const beforeByLeaf = new Map(before.map((member) => [member.leafIndex, member]));
  for (const proposal of commit.proposals) {
    if (proposal.kind !== 'update' || proposal.leafIndex === undefined) continue;
    const prior = beforeByLeaf.get(proposal.leafIndex);
    if (!prior || !proposal.credential || !sameIdentity(prior.credential, proposal.credential)) return false;
  }
  const addedKeys = new Set(
    commit.proposals.flatMap((proposal) => (proposal.kind === 'add' && proposal.added ? [toBase64(proposal.added.signatureKey)] : [])),
  );
  const committerBefore = beforeByLeaf.get(commit.committer.leafIndex);
  const committerAfter = after.find((member) => member.leafIndex === commit.committer.leafIndex);
  if (committerBefore && committerAfter && !sameIdentity(committerBefore.credential, committerAfter.credential)) return false;
  for (const member of after) {
    const prior = beforeByLeaf.get(member.leafIndex);
    if (!prior) {
      if (!addedKeys.has(toBase64(member.signatureKey))) return false;
      continue;
    }
    if (addedKeys.has(toBase64(member.signatureKey))) continue;
    if (!sameIdentity(prior.credential, member.credential)) return false;
  }
  return true;
}

function keyPackageFromMessage(message: Uint8Array): KeyPackage {
  const decoded = decodeMlsMessage(message, 0);
  if (!decoded || decoded[0].wireformat !== 'mls_key_package') {
    throw new MlsOperationError('mls_error', 'add is not an MLS KeyPackage message');
  }
  return decoded[0].keyPackage;
}

function encodeStored(stored: StoredKeyMaterial): Uint8Array {
  return new TlsWriter()
    .opaque(encodeKeyPackage(stored.keyPackage))
    .opaque(stored.privateKeys.initPrivateKey)
    .opaque(stored.privateKeys.hpkePrivateKey)
    .opaque(stored.privateKeys.signaturePrivateKey)
    .finish();
}

function decodeStored(bytes: Uint8Array): StoredKeyMaterial {
  const r = new TlsReader(bytes);
  const encoded = r.opaque();
  const initPrivateKey = r.opaque();
  const hpkePrivateKey = r.opaque();
  const signaturePrivateKey = r.opaque();
  r.end();
  const decoded = decodeKeyPackage(encoded, 0);
  if (!decoded || decoded[1] !== encoded.length) throw new MlsOperationError('mls_error', 'stored key package is truncated');
  return { keyPackage: decoded[0], privateKeys: { initPrivateKey, hpkePrivateKey, signaturePrivateKey } };
}

function memberFromLeaf(leaf: LeafNode, leafIndex: number): Member | undefined {
  if (leaf.credential.credentialType !== 'basic') return undefined;
  try {
    return {
      leafIndex,
      signatureKey: leaf.signaturePublicKey.slice(),
      credential: decodeBridgeCredential(leaf.credential.identity),
    };
  } catch {
    return undefined;
  }
}

function memberAt(client: ClientState, leafIndex: number): Member | undefined {
  if (!Number.isInteger(leafIndex) || leafIndex < 0) return undefined;
  const node = client.ratchetTree[leafIndex * 2];
  if (node?.nodeType !== 'leaf') return undefined;
  return memberFromLeaf(node.leaf, leafIndex);
}

function summarizeProposal(client: ClientState, proposal: Proposal, senderLeafIndex: number | undefined): ProposalSummary {
  switch (proposal.proposalType) {
    case 'add':
      return { kind: 'add', added: memberFromLeaf(proposal.add.keyPackage.leafNode, -1) };
    case 'remove':
      return { kind: 'remove', removed: memberAt(client, proposal.remove.removed) };
    case 'update':
      return {
        kind: 'update',
        leafIndex: senderLeafIndex,
        credential: memberFromLeaf(proposal.update.leafNode, senderLeafIndex ?? -1)?.credential,
      };
    case 'psk':
      return { kind: 'psk' };
    case 'reinit':
      return { kind: 'reinit' };
    case 'external_init':
      return { kind: 'external_init' };
    case 'group_context_extensions':
      return { kind: 'group_context_extensions' };
    default:
      return { kind: 'custom', proposalType: proposal.proposalType };
  }
}

function ratchetFingerprint(tree: SecretTree): string[] {
  return tree.map((node) => {
    if (!node) return '-';
    return `${node.application.generation}:${Object.keys(node.application.unusedGenerations).length}`;
  });
}

function changedLeaf(before: string[], after: string[]): number {
  const changed: number[] = [];
  const width = Math.max(before.length, after.length);
  for (let i = 0; i < width; i++) {
    if ((before[i] ?? '-') !== (after[i] ?? '-')) changed.push(i);
  }
  if (changed.length !== 1) {
    throw new MlsOperationError('mls_error', `could not identify the application sender (${changed.length} ratchets changed)`);
  }
  // ts-mls's secret tree is indexed like the ratchet tree: leaves sit at even
  // node indexes. An application message advances that one leaf.
  const nodeIndex = changed[0]!;
  if (nodeIndex % 2 !== 0) {
    throw new MlsOperationError('mls_error', `application ratchet advanced at parent node ${nodeIndex}`);
  }
  return nodeIndex / 2;
}
