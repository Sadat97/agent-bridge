import { randomBytes, randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  addApprovalContent,
  bytesEqual,
  encodeBridgeCredential,
  encodeCommitApprovals,
  generateEd25519KeyPair,
  issueDeviceCert,
  SignatureLabel,
  signWithLabel,
  utf8,
} from '@agent-bridge/protocol';
import { createCommit, defaultCapabilities, defaultLifetime, encodeMlsMessage, generateKeyPackage, getCiphersuiteFromName, getCiphersuiteImpl } from 'ts-mls';
import { debugClientState } from '../src/ts-mls-engine.ts';
import { createTsMlsEngine, encodeEnvelope, replenishKeyPackages } from '../src/index.ts';
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

  it('halts when a commit removes a leaf that carries the topic owner identity', async () => {
    const carol = makePerson('carol');
    const { alice, topicId, owner, board, session } = await connected([carol]);
    const carolSession = session.get(carol)!;
    // MLS rejects a commit that removes the committer, so the owner's own leaf
    // never becomes a ciphertext. A second leaf certified by the owner's identity
    // key is a real Remove, and section 5.8 still refuses it.
    await expect(owner.engine.commit(owner.confirmedState(), { removes: [0], authenticatedData: new Uint8Array() })).rejects.toThrow(/removing committer/);

    const device = generateEd25519KeyPair();
    const deviceId = randomUUID();
    const deviceCert = issueDeviceCert(alice.identity.privateKey, {
      handle: 'alice',
      deviceId,
      signatureKey: device.publicKey,
      createdAt: Math.floor(Date.now() / 1000),
    });
    const extra = createTsMlsEngine({ devicePrivateKey: device.privateKey });
    const [keyPackage] = await extra.generateKeyPackages(1, {
      handle: 'alice',
      identityKey: alice.identity.publicKey,
      deviceId,
      deviceCert,
    });
    const expiresAt = later();
    const approvalId = 'apr-owner-device';
    const signature = signWithLabel(
      alice.identity.privateKey,
      SignatureLabel.add,
      addApprovalContent({
        topicId,
        approvalId,
        inviteeIdentityKey: alice.identity.publicKey,
        inviteeDeviceKey: device.publicKey,
        role: 'member',
        expiresAt,
      }),
    );
    const added = await owner.stageCommit({
      adds: [{ keyPackage: keyPackage!.publicKeyPackage, approvalId, expiresAt, signature }],
    });
    await board.post(owner, added, [carolSession]);
    const epoch = carolSession.epoch;
    const ownerLeaf = owner.members().find((member) => bytesEqual(member.signatureKey, device.publicKey));
    if (!ownerLeaf) throw new Error('owner identity leaf missing');
    const copy = owner.engine.deserialize(owner.engine.serialize(owner.confirmedState()));
    const removal = await owner.engine.commit(copy, { removes: [ownerLeaf.leafIndex], authenticatedData: new Uint8Array() });
    expect(await carolSession.receive(board.seq + 1, removal.commit)).toMatchObject({
      kind: 'halted',
      reason: 'remove targets the topic owner',
    });
    expect(carolSession.epoch).toBe(epoch);
  });

  it('rejects a leave whose author.handle does not match the sender', async () => {
    const bob = makePerson('bob');
    const carol = makePerson('carol');
    const { owner, board, session } = await connected([bob, carol]);
    const bobSession = session.get(bob)!;
    const carolSession = session.get(carol)!;
    const epoch = carolSession.epoch;
    const copy = bob.engine.deserialize(bob.engine.serialize(bobSession.confirmedState()));
    const encrypted = await bob.engine.encrypt(
      copy,
      encodeEnvelope({
        v: 1,
        id: 'msg_mismatch_leave',
        type: 'leave',
        ts: new Date().toISOString(),
        author: { handle: 'alice' },
        reply_to: null,
        payload: {},
        approval: null,
      }),
    );
    const seq = board.seq + 1;
    expect((await owner.receive(seq, encrypted.message)).kind).toBe('application');
    expect((await carolSession.receive(seq, encrypted.message)).kind).toBe('application');
    const bobLeaf = owner.members().find((member) => member.credential.handle === 'bob')!.leafIndex;
    const cited = encodeCommitApprovals({
      adds: [],
      removes: [{ kind: 'leave', approvalId: 'apr-mismatch', deviceKey: bob.device.publicKey, leaveSeq: seq }],
    });
    const ownerCopy = owner.engine.deserialize(owner.engine.serialize(owner.confirmedState()));
    const bad = await owner.engine.commit(ownerCopy, { removes: [bobLeaf], authenticatedData: cited });
    expect(await carolSession.receive(seq + 1, bad.commit)).toMatchObject({
      kind: 'halted',
      reason: 'leave_seq is not a leave message',
    });
    expect(carolSession.epoch).toBe(epoch);
  });

  it('rejects a self-update that rebinds the leaf credential', async () => {
    const impl = await getCiphersuiteImpl(getCiphersuiteFromName('MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519'));
    for (const variant of ['new-handle', 'new-identity'] as const) {
      const bob = makePerson('bob');
      const carol = makePerson('carol');
      const { board, session } = await connected([bob, carol]);
      const bobSession = session.get(bob)!;
      const carolSession = session.get(carol)!;
      const epoch = carolSession.epoch;
      const handles = carolSession.members().map((member) => member.credential.handle).sort();
      const sara = makePerson('sara');
      const identity = variant === 'new-identity' ? sara.identity : bob.identity;
      const deviceCert = issueDeviceCert(identity.privateKey, {
        handle: 'sara',
        deviceId: bob.deviceId,
        signatureKey: bob.device.publicKey,
        createdAt: Math.floor(Date.now() / 1000),
      });
      const client = debugClientState(bob.engine.deserialize(bob.engine.serialize(bobSession.confirmedState())));
      const node = client.ratchetTree[client.privatePath.leafIndex * 2];
      if (node?.nodeType !== 'leaf') throw new Error('missing leaf');
      node.leaf = {
        ...node.leaf,
        credential: {
          credentialType: 'basic',
          identity: encodeBridgeCredential({
            handle: 'sara',
            identityKey: identity.publicKey,
            deviceId: bob.deviceId,
            deviceCert,
          }),
        },
      };
      const committed = await createCommit(
        { state: client, cipherSuite: impl },
        { extraProposals: [], ratchetTreeExtension: true, authenticatedData: new Uint8Array() },
      );
      const message = encodeMlsMessage(committed.commit);
      expect(await carolSession.receive(board.seq + 1, message)).toMatchObject({
        kind: 'halted',
        reason: 'credential changed',
      });
      expect(carolSession.epoch).toBe(epoch);
      expect(carolSession.members().map((member) => member.credential.handle).sort()).toEqual(handles);
      expect(carol.store.pins.has('sara')).toBe(false);
    }
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
