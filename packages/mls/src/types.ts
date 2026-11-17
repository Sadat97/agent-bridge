// MlsEngine (DESIGN.md section 5.12). Group state is opaque and
// engine-specific; only these methods cross the boundary.

import type { BridgeCredential } from '@agent-bridge/protocol';

export const TS_MLS_ENGINE_ID = 'ts-mls@1.6.4';

/** Public identity placed in the MLS basic credential. */
export type Credential = BridgeCredential;

export type LeafIndex = number;

export interface Member {
  /**
   * Leaf index in the current tree. An added leaf is not in the tree yet;
   * its index is -1 until the commit is applied.
   */
  leafIndex: LeafIndex;
  signatureKey: Uint8Array;
  credential: Credential;
}

export type ProposalSummary =
  | { kind: 'add'; added?: Member }
  | { kind: 'remove'; removed?: Member }
  | { kind: 'update'; leafIndex?: LeafIndex }
  | { kind: 'psk' }
  | { kind: 'reinit' }
  | { kind: 'external_init' }
  | { kind: 'group_context_extensions' }
  | { kind: 'custom'; proposalType: number };

/** What `process` shows the commit callback. Authenticated data is already decrypted. */
export interface CommitInspection {
  committer: Member;
  proposals: ProposalSummary[];
  /** CommitApprovals, or empty when the commit does not add or remove. */
  authenticatedData: Uint8Array;
}

export interface GroupState {
  readonly engineId: string;
}

export interface GeneratedKeyPackage {
  /** MLSMessage carrying the KeyPackage, the bytes the relay stores. */
  publicKeyPackage: Uint8Array;
  /** RFC 9420 KeyPackageRef for cipher suite 1. */
  ref: Uint8Array;
  /**
   * Opaque blob the same engine needs in order to join a Welcome built for
   * this KeyPackage. Treat it as secret.
   */
  privateKeyPackage: Uint8Array;
}

export interface CommitChange {
  /** MLSMessages carrying KeyPackages. */
  adds?: Uint8Array[];
  removes?: LeafIndex[];
  /** CommitApprovals. Empty when the commit does not add or remove. */
  authenticatedData: Uint8Array;
}

export type ProcessResult =
  | { kind: 'application'; sender: Member; plaintext: Uint8Array; next: GroupState }
  | { kind: 'commit'; committer: Member; added: Member[]; removed: Member[]; next: GroupState }
  | { kind: 'rejected'; reason: string };

export interface MlsEngine {
  readonly id: string;
  generateKeyPackages(n: number, cred: Credential): Promise<GeneratedKeyPackage[]>;
  createGroup(groupId: Uint8Array, cred: Credential): Promise<GroupState>;
  join(welcome: Uint8Array, privateKeyPackage: Uint8Array): Promise<GroupState>;
  commit(
    state: GroupState,
    change: CommitChange,
  ): Promise<{ commit: Uint8Array; welcome?: Uint8Array; pending: GroupState }>;
  encrypt(state: GroupState, plaintext: Uint8Array): Promise<{ message: Uint8Array; next: GroupState }>;
  /**
   * `validateCommit` runs after the commit is decrypted and before it is
   * applied. Returning false yields `rejected` and leaves `state` unchanged.
   * The callback is synchronous: signature checks in `@agent-bridge/protocol` are.
   */
  process(
    state: GroupState,
    message: Uint8Array,
    validateCommit: (commit: CommitInspection) => boolean,
  ): Promise<ProcessResult>;
  members(state: GroupState): Member[];
  epoch(state: GroupState): bigint;
  /** MLS group_id. For a topic this is the 16 raw bytes of the topic id. */
  groupId(state: GroupState): Uint8Array;
  serialize(state: GroupState): Uint8Array;
  deserialize(bytes: Uint8Array): GroupState;
}
