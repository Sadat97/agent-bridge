import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import {
  addApprovalContent,
  generateEd25519KeyPair,
  issueDeviceCert,
  removeApprovalContent,
  SignatureLabel,
  signWithLabel,
} from '@agent-bridge/protocol';
import type { Ed25519KeyPair } from '@agent-bridge/protocol';
import { createTsMlsEngine, MlsStore, replenishKeyPackages, TopicSession } from '../src/index.ts';
import type { Credential, MlsEngine, StagedOutbound } from '../src/index.ts';

export interface TestPerson {
  handle: string;
  identity: Ed25519KeyPair;
  device: Ed25519KeyPair;
  deviceId: string;
  credential: Credential;
  dir: string;
  /** Path of this person's SQLite file, so a test can reopen it. */
  storePath: string;
  store: MlsStore;
  engine: MlsEngine;
}

export function makePerson(handle: string): TestPerson {
  const identity = generateEd25519KeyPair();
  const device = generateEd25519KeyPair();
  const deviceId = randomUUID();
  const deviceCert = issueDeviceCert(identity.privateKey, {
    handle,
    deviceId,
    signatureKey: device.publicKey,
    createdAt: Math.floor(Date.now() / 1000),
  });
  const credential: Credential = { handle, identityKey: identity.publicKey, deviceId, deviceCert };
  const dir = mkdtempSync(join(tmpdir(), `agb-${handle}-`));
  const storePath = join(dir, 'store.sqlite');
  const store = new MlsStore(storePath);
  const engine = createTsMlsEngine({ devicePrivateKey: device.privateKey, pins: store.pins });
  return { handle, identity, device, deviceId, credential, dir, storePath, store, engine };
}

export function reopen(person: TestPerson, topicId: string): TopicSession {
  person.store.close();
  person.store = new MlsStore(person.storePath);
  person.engine = createTsMlsEngine({ devicePrivateKey: person.device.privateKey, pins: person.store.pins });
  return TopicSession.open(person.store, person.engine, topicId);
}

export function signAdd(
  owner: TestPerson,
  topicId: string,
  approvalId: string,
  invitee: TestPerson,
  expiresAt: number,
): Uint8Array {
  return signWithLabel(
    owner.identity.privateKey,
    SignatureLabel.add,
    addApprovalContent({
      topicId,
      approvalId,
      inviteeIdentityKey: invitee.identity.publicKey,
      inviteeDeviceKey: invitee.device.publicKey,
      role: 'member',
      expiresAt,
    }),
  );
}

export function signRemove(owner: TestPerson, topicId: string, approvalId: string, removed: TestPerson): Uint8Array {
  return signWithLabel(
    owner.identity.privateKey,
    SignatureLabel.remove,
    removeApprovalContent({ topicId, approvalId, removedDeviceKey: removed.device.publicKey }),
  );
}

export function later(seconds = 3600): number {
  return Math.floor(Date.now() / 1000) + seconds;
}

/** In-process stand-in for the relay's per-topic sequence. */
export class Board {
  seq = 0;

  async post(sender: TopicSession, staged: StagedOutbound, recipients: TopicSession[]): Promise<number> {
    this.seq += 1;
    await sender.confirmStaged(this.seq);
    for (const recipient of recipients) {
      if (recipient.status === 'left' || recipient.status === 'halted') continue;
      await recipient.receive(this.seq, staged.message);
    }
    return this.seq;
  }
}

/** Alice owns the topic and adds each person, in order. */
export async function connected(members: TestPerson[]): Promise<{
  alice: TestPerson;
  topicId: string;
  owner: TopicSession;
  board: Board;
  session: Map<TestPerson, TopicSession>;
}> {
  const alice = makePerson('alice');
  const topicId = randomUUID();
  const owner = await TopicSession.create({
    store: alice.store,
    engine: alice.engine,
    topicId,
    credential: alice.credential,
  });
  const board = new Board();
  const session = new Map<TestPerson, TopicSession>([[alice, owner]]);
  for (const member of members) {
    const [keyPackage] = await replenishKeyPackages(member.engine, member.credential, member.store, 1);
    const approvalId = `apr-${member.handle}-${board.seq + 1}`;
    const expiresAt = later();
    const staged = await owner.stageCommit({
      adds: [{
        keyPackage: keyPackage!,
        approvalId,
        expiresAt,
        signature: signAdd(alice, topicId, approvalId, member, expiresAt),
      }],
    });
    const others = [...session.values()].filter((existing) => existing !== owner);
    const seq = await board.post(owner, staged, others);
    const joined = await TopicSession.join({
      store: member.store,
      engine: member.engine,
      topicId,
      welcome: staged.welcome!,
      credential: member.credential,
      ownerIdentityKey: alice.identity.publicKey,
      commitSeq: seq,
    });
    await joined.acceptJoin();
    session.set(member, joined);
  }
  return { alice, topicId, owner, board, session };
}
