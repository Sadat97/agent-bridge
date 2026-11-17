import { randomBytes, randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  addApprovalContent,
  encodeCommitApprovals,
  SignatureLabel,
  signWithLabel,
  utf8,
} from '@agent-bridge/protocol';
import { defaultCapabilities, defaultLifetime, generateKeyPackage, getCiphersuiteFromName, getCiphersuiteImpl } from 'ts-mls';
import { evaluateCommit, replenishKeyPackages } from '../src/index.ts';
import { rawCommit } from './attack.ts';
import { connected, later, makePerson, reopen, signAdd, signRemove } from './helpers.ts';

async function deliverAttack(sessions: Array<{ receive: (seq: number, message: Uint8Array) => Promise<{ kind: string }> }>, seq: number, message: Uint8Array) {
  const results = [];
  for (const session of sessions) results.push(await session.receive(seq, message));
  return results;
}

describe('commit validation', () => {
  it('halts every other bridge on a hidden add, and the planted member gets nothing afterwards', async () => {
    const bob = makePerson('bob');
    const carol = makePerson('carol');
    const eve = makePerson('eve');
    const { alice, topicId, owner, board, session } = await connected([bob, carol]);
    const bobSession = session.get(bob)!;
    const carolSession = session.get(carol)!;
    const epoch = owner.epoch;
    const [evePackage] = await replenishKeyPackages(eve.engine, eve.credential, eve.store, 1);
    const copy = bob.engine.deserialize(bob.engine.serialize(bobSession.confirmedState()));
    const hidden = await bob.engine.commit(copy, {
      adds: [evePackage!],
      authenticatedData: new Uint8Array(),
    });

    const seq = board.seq + 1;
    const results = await deliverAttack([owner, carolSession], seq, hidden.commit);
    expect(results).toEqual([
      expect.objectContaining({ kind: 'halted', reason: expect.stringMatching(/topic owner/) }),
      expect.objectContaining({ kind: 'halted', reason: expect.stringMatching(/topic owner/) }),
    ]);
    expect(owner.epoch).toBe(epoch);
    expect(owner.lastSeq).toBe(board.seq);
    expect(carolSession.lastSeq).toBe(board.seq);
    await expect(owner.stageMessage({ type: 'update', body: 'after the hidden add' })).rejects.toMatchObject({ code: 'topic_halted' });
    await expect(carolSession.stageCommit()).rejects.toMatchObject({ code: 'topic_halted' });
    expect(owner.staged()).toBeUndefined();

    const planted = await TopicSessionJoin(eve, topicId, hidden.welcome!, alice, seq);
    expect(planted.epoch).toBe(epoch + 1n);
    const stale = await owner.engine.encrypt(owner.confirmedState(), utf8('not for eve'));
    await expect(eve.engine.process(planted.confirmedState(), stale.message, () => true)).rejects.toThrow();

    const restarted = reopen(alice, topicId);
    expect(restarted.status).toBe('halted');
    expect(restarted.epoch).toBe(epoch);
    expect(restarted.staged()).toBeUndefined();
    await expect(restarted.stageMessage({ type: 'update', body: 'still halted' })).rejects.toMatchObject({ code: 'topic_halted' });
  });

  it('rejects an add the authenticated data does not cover, and entries with no proposal', async () => {
    const bob = makePerson('bob');
    const carol = makePerson('carol');
    const eve = makePerson('eve');
    const { alice, topicId, owner, board, session } = await connected([bob, carol]);
    const expiresAt = later();
    const [evePackage] = await eve.engine.generateKeyPackages(1, eve.credential);
    const copy = owner.engine.deserialize(owner.engine.serialize(owner.confirmedState()));
    const covered = encodeCommitApprovals({
      adds: [{
        approvalId: 'apr-for-bob',
        deviceKey: bob.device.publicKey,
        expiresAt,
        signature: signAdd(alice, topicId, 'apr-for-bob', bob, expiresAt),
      }],
      removes: [],
    });
    const wrongLeaf = await owner.engine.commit(copy, { adds: [evePackage!.publicKeyPackage], authenticatedData: covered });
    const seq = board.seq + 1;
    expect(await session.get(carol)!.receive(seq, wrongLeaf.commit)).toMatchObject({
      kind: 'halted',
      reason: expect.stringMatching(/do not match/),
    });
    expect(session.get(carol)!.epoch).toBe(owner.epoch);

    const frank = makePerson('frank');
    const bob2 = makePerson('bob');
    const carol2 = makePerson('carol');
    const { owner: owner2, board: board2, session: session2, alice: alice2, topicId: topic2 } = await connected([bob2, carol2]);
    const [eve2] = await eve.engine.generateKeyPackages(1, eve.credential);
    const [frankPackage] = await frank.engine.generateKeyPackages(1, frank.credential);
    const extra = encodeCommitApprovals({
      adds: [
        entry(alice2, topic2, 'apr-eve', eve, expiresAt),
        entry(alice2, topic2, 'apr-frank', frank, expiresAt),
      ],
      removes: [],
    });
    const copy2 = owner2.engine.deserialize(owner2.engine.serialize(owner2.confirmedState()));
    const extraCommit = await owner2.engine.commit(copy2, { adds: [eve2!.publicKeyPackage], authenticatedData: extra });
    expect(await session2.get(carol2)!.receive(board2.seq + 1, extraCommit.commit)).toMatchObject({
      kind: 'halted',
      reason: expect.stringMatching(/do not match/),
    });

    const gina = makePerson('gina');
    const { alice: alice3, topicId: topic3, owner: owner3, board: board3, session: session3 } = await connected([gina]);
    const dana = makePerson('dana');
    const [danaPackage] = await dana.engine.generateKeyPackages(1, dana.credential);
    const [frankAgain] = await frank.engine.generateKeyPackages(1, frank.credential);
    const onlyDana = encodeCommitApprovals({
      adds: [entry(alice3, topic3, 'apr-dana', dana, expiresAt)],
      removes: [],
    });
    const copy3 = owner3.engine.deserialize(owner3.engine.serialize(owner3.confirmedState()));
    const missing = await owner3.engine.commit(copy3, {
      adds: [danaPackage!.publicKeyPackage, frankAgain!.publicKeyPackage],
      authenticatedData: onlyDana,
    });
    expect(await session3.get(gina)!.receive(board3.seq + 1, missing.commit)).toMatchObject({
      kind: 'halted',
      reason: expect.stringMatching(/do not match/),
    });
  });

  it('rejects a forged signature and a signature from the wrong identity key', async () => {
    const bob = makePerson('bob');
    const carol = makePerson('carol');
    const eve = makePerson('eve');
    const { alice, topicId, owner, board, session } = await connected([bob, carol]);
    const expiresAt = later();
    const [evePackage] = await eve.engine.generateKeyPackages(1, eve.credential);
    const forged = encodeCommitApprovals({
      adds: [{ approvalId: 'apr-forged', deviceKey: eve.device.publicKey, expiresAt, signature: randomBytes(64) }],
      removes: [],
    });
    const copy = owner.engine.deserialize(owner.engine.serialize(owner.confirmedState()));
    const forgedCommit = await owner.engine.commit(copy, { adds: [evePackage!.publicKeyPackage], authenticatedData: forged });
    expect(await session.get(bob)!.receive(board.seq + 1, forgedCommit.commit)).toMatchObject({
      kind: 'halted',
      reason: expect.stringMatching(/signature is invalid/),
    });

    const carol2 = makePerson('carol');
    const { owner: owner2, board: board2, session: session2, topicId: topic2 } = await connected([carol2]);
    const [eve2] = await eve.engine.generateKeyPackages(1, eve.credential);
    const wrongForTopic = signWithLabel(
      bob.identity.privateKey,
      SignatureLabel.add,
      addApprovalContent({
        topicId: topic2,
        approvalId: 'apr-wrong-key',
        inviteeIdentityKey: eve.identity.publicKey,
        inviteeDeviceKey: eve.device.publicKey,
        role: 'member',
        expiresAt,
      }),
    );
    const authenticated = encodeCommitApprovals({
      adds: [{ approvalId: 'apr-wrong-key', deviceKey: eve.device.publicKey, expiresAt, signature: wrongForTopic }],
      removes: [],
    });
    const copy2 = owner2.engine.deserialize(owner2.engine.serialize(owner2.confirmedState()));
    const wrongCommit = await owner2.engine.commit(copy2, { adds: [eve2!.publicKeyPackage], authenticatedData: authenticated });
    expect(await session2.get(carol2)!.receive(board2.seq + 1, wrongCommit.commit)).toMatchObject({
      kind: 'halted',
      reason: expect.stringMatching(/signature is invalid/),
    });
  });

  it('rejects a replayed approval id after the member was removed and re-added', async () => {
    const bob = makePerson('bob');
    const carol = makePerson('carol');
    const { alice, topicId, owner, board, session } = await connected([carol]);
    const expiresAt = later();
    const approvalId = 'apr-replay';
    const [firstPackage] = await replenishKeyPackages(bob.engine, bob.credential, bob.store, 1);
    const signature = signAdd(alice, topicId, approvalId, bob, expiresAt);
    const staged = await owner.stageCommit({
      adds: [{ keyPackage: firstPackage!, approvalId, expiresAt, signature }],
    });
    const addSeq = await board.post(owner, staged, [session.get(carol)!]);
    const bobSession = await TopicSessionJoin(bob, topicId, staged.welcome!, alice, addSeq);
    await bobSession.acceptJoin();

    const bobLeaf = owner.members().find((member) => member.credential.handle === 'bob')!.leafIndex;
    const removed = await owner.stageCommit({
      removes: [{ leafIndex: bobLeaf, approvalId: 'apr-remove-bob', signature: signRemove(alice, topicId, 'apr-remove-bob', bob) }],
    });
    await board.post(owner, removed, [session.get(carol)!, bobSession]);
    expect(bobSession.status).toBe('left');

    const [secondPackage] = await bob.engine.generateKeyPackages(1, bob.credential);
    const replay = encodeCommitApprovals({
      adds: [{ approvalId, deviceKey: bob.device.publicKey, expiresAt, signature }],
      removes: [],
    });
    const copy = owner.engine.deserialize(owner.engine.serialize(owner.confirmedState()));
    const again = await owner.engine.commit(copy, { adds: [secondPackage!.publicKeyPackage], authenticatedData: replay });
    expect(await session.get(carol)!.receive(board.seq + 1, again.commit)).toMatchObject({
      kind: 'halted',
      reason: expect.stringMatching(/already used/),
    });
    expect(session.get(carol)!.epoch).toBe(owner.epoch);
  });

  it('rejects a leave_seq that is not a leave, including another member\'s message', async () => {
    const bob = makePerson('bob');
    const carol = makePerson('carol');
    const { alice, topicId, owner, board, session } = await connected([bob, carol]);
    const bobSession = session.get(bob)!;
    const carolSession = session.get(carol)!;

    const update = await bobSession.stageMessage({ type: 'update', body: 'not a leave' });
    const updateSeq = await board.post(bobSession, update, [owner, carolSession]);
    const bobLeaf = owner.members().find((member) => member.credential.handle === 'bob')!.leafIndex;
    const notLeave = encodeCommitApprovals({
      adds: [],
      removes: [{ kind: 'leave', approvalId: 'apr-not-leave', deviceKey: bob.device.publicKey, leaveSeq: updateSeq }],
    });
    const copy = owner.engine.deserialize(owner.engine.serialize(owner.confirmedState()));
    const bad = await owner.engine.commit(copy, { removes: [bobLeaf], authenticatedData: notLeave });
    expect(await carolSession.receive(board.seq + 1, bad.commit)).toMatchObject({
      kind: 'halted',
      reason: 'leave_seq is not a leave message',
    });
    expect(carolSession.epoch).toBe(owner.epoch);

    const bob2 = makePerson('bob');
    const carol2 = makePerson('carol');
    const { owner: owner2, board: board2, session: session2 } = await connected([bob2, carol2]);
    const carolUpdate = await session2.get(carol2)!.stageMessage({ type: 'question', body: 'from carol' });
    const carolSeq = await board2.post(session2.get(carol2)!, carolUpdate, [owner2, session2.get(bob2)!]);
    const leaf = owner2.members().find((member) => member.credential.handle === 'bob')!.leafIndex;
    const cited = encodeCommitApprovals({
      adds: [],
      removes: [{ kind: 'leave', approvalId: 'apr-wrong-sender', deviceKey: bob2.device.publicKey, leaveSeq: carolSeq }],
    });
    const copy2 = owner2.engine.deserialize(owner2.engine.serialize(owner2.confirmedState()));
    const wrongSender = await owner2.engine.commit(copy2, { removes: [leaf], authenticatedData: cited });
    expect(await session2.get(bob2)!.receive(board2.seq + 1, wrongSender.commit)).toMatchObject({
      kind: 'halted',
      reason: 'leave_seq was not sent by the removed member',
    });
  });

  it('halts on an unsupported proposal and on a leaf whose certificate does not chain', async () => {
    const bob = makePerson('bob');
    const { owner, board, session } = await connected([bob]);
    const bobSession = session.get(bob)!;
    const epoch = bobSession.epoch;
    const extensions = await rawCommit(owner.engine, owner.confirmedState(), [
      { proposalType: 'group_context_extensions', groupContextExtensions: { extensions: [] } },
    ]);
    expect(await bobSession.receive(board.seq + 1, extensions.commit)).toMatchObject({
      kind: 'halted',
      reason: expect.stringMatching(/unsupported proposal group_context_extensions/),
    });
    expect(bobSession.epoch).toBe(epoch);

    const bob2 = makePerson('bob');
    const { owner: owner2, board: board2, session: session2 } = await connected([bob2]);
    const psk = await rawCommit(
      owner2.engine,
      owner2.confirmedState(),
      [{ proposalType: 'psk', psk: { preSharedKeyId: { psktype: 'external', pskId: Uint8Array.of(9), pskNonce: new Uint8Array(16) } } }],
      new Uint8Array(),
      true,
    );
    const before = session2.get(bob2)!.epoch;
    expect((await session2.get(bob2)!.receive(board2.seq + 1, psk.commit)).kind).toBe('halted');
    expect(session2.get(bob2)!.epoch).toBe(before);
    expect(session2.get(bob2)!.haltReason).toMatch(/psk/i);

    const bob3 = makePerson('bob');
    const { owner: owner3, board: board3, session: session3 } = await connected([bob3]);
    const impl = await getCiphersuiteImpl(getCiphersuiteFromName('MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519'));
    const evil = await generateKeyPackage(
      { credentialType: 'basic', identity: utf8('not-a-bridge-credential') },
      defaultCapabilities(),
      defaultLifetime,
      [],
      impl,
    );
    const badLeaf = await rawCommit(
      owner3.engine,
      owner3.confirmedState(),
      [{ proposalType: 'add', add: { keyPackage: evil.publicPackage } }],
      new Uint8Array(),
      true,
    );
    const epoch3 = session3.get(bob3)!.epoch;
    expect((await session3.get(bob3)!.receive(board3.seq + 1, badLeaf.commit)).kind).toBe('halted');
    expect(session3.get(bob3)!.epoch).toBe(epoch3);
    expect(session3.get(bob3)!.haltReason).toMatch(/credential/i);
  });

  it('rejects a commit that would remove the topic owner', () => {
    const alice = makePerson('alice');
    const ownerKey = alice.identity.publicKey;
    const member = {
      leafIndex: 0,
      signatureKey: alice.device.publicKey,
      credential: alice.credential,
    };
    const decision = evaluateCommit(
      {
        committer: member,
        proposals: [{ kind: 'remove', removed: member }],
        authenticatedData: encodeCommitApprovals({
          adds: [],
          removes: [{ kind: 'leave', approvalId: 'apr-owner', deviceKey: alice.device.publicKey, leaveSeq: 1 }],
        }),
      },
      {
        topicId: randomUUID(),
        ownerIdentityKey: ownerKey,
        consumedApprovalIds: new Set(),
        messages: new Map([[1, { signatureKey: alice.device.publicKey, type: 'leave', authorMatches: true }]]),
        pinnedIdentity: () => ownerKey,
      },
    );
    expect(decision).toMatchObject({ ok: false, reason: 'remove targets the topic owner' });
  });
});

function entry(owner: ReturnType<typeof makePerson>, topicId: string, approvalId: string, invitee: ReturnType<typeof makePerson>, expiresAt: number) {
  return {
    approvalId,
    deviceKey: invitee.device.publicKey,
    expiresAt,
    signature: signAdd(owner, topicId, approvalId, invitee, expiresAt),
  };
}

function TopicSessionJoin(
  person: ReturnType<typeof makePerson>,
  topicId: string,
  welcome: Uint8Array,
  alice: ReturnType<typeof makePerson>,
  commitSeq: number,
) {
  return import('../src/index.ts').then(({ TopicSession }) =>
    TopicSession.join({
      store: person.store,
      engine: person.engine,
      topicId,
      welcome,
      credential: person.credential,
      ownerIdentityKey: alice.identity.publicKey,
      commitSeq,
    }),
  );
}
