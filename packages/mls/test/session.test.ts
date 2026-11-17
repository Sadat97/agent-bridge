import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { uuidToBytes } from '@agent-bridge/protocol';
import { replenishKeyPackages, TopicSession, UNPUBLISHED_GENERATION_SKIP } from '../src/index.ts';
import { connected, later, makePerson, reopen, signAdd, signRemove } from './helpers.ts';

describe('multi-member sessions', () => {
  it('adds, talks, self-updates, removes by leave and by approval, across epochs', async () => {
    const bob = makePerson('bob');
    const carol = makePerson('carol');
    const dan = makePerson('dan');
    const { alice, topicId, owner, board, session } = await connected([bob, carol, dan]);
    const bobSession = session.get(bob)!;
    const carolSession = session.get(carol)!;
    const danSession = session.get(dan)!;
    expect(owner.epoch).toBe(3n);
    expect(danSession.members().map((member) => member.credential.handle).sort()).toEqual(['alice', 'bob', 'carol', 'dan']);

    const hello = await bobSession.stageMessage({ type: 'update', body: 'train at 09:12', authorAgent: 'claude-code' });
    await board.post(bobSession, hello, [owner, carolSession, danSession]);
    expect(owner.lastSeq).toBe(board.seq);

    // A staged send is dropped when someone else's commit wins the epoch.
    const abandoned = await owner.stageMessage({ type: 'question', body: 'which platform?' });
    const rotated = await bobSession.stageCommit();
    expect(rotated.kind).toBe('commit');
    expect(rotated.adds).toEqual([]);
    await board.post(bobSession, rotated, [owner, carolSession, danSession]);
    expect(owner.staged()).toBeUndefined();
    expect(owner.epoch).toBe(4n);
    expect(abandoned.message).not.toEqual(owner.staged()?.message);

    const afterUpdate = await danSession.stageMessage({ type: 'answer', body: 'platform 4' });
    await board.post(danSession, afterUpdate, [owner, bobSession, carolSession]);
    expect(bobSession.members().find((member) => member.credential.handle === 'bob')!.signatureKey).toEqual(bob.device.publicKey);

    const leaving = await carolSession.stageMessage({ type: 'leave' });
    const leaveSeq = await board.post(carolSession, leaving, [owner, bobSession, danSession]);
    const carolLeaf = owner.members().find((member) => member.credential.handle === 'carol')!.leafIndex;
    const removedCarol = await owner.stageCommit({
      removes: [{ leafIndex: carolLeaf, approvalId: 'apr-carol-leave', leaveSeq }],
    });
    await board.post(owner, removedCarol, [bobSession, carolSession, danSession]);
    expect(carolSession.status).toBe('left');
    await expect(carolSession.stageMessage({ type: 'update', body: 'still here' })).rejects.toMatchObject({ code: 'topic_left' });

    const withoutCarol = await danSession.stageMessage({ type: 'update', body: 'carol left' });
    await board.post(danSession, withoutCarol, [owner, bobSession, carolSession]);
    expect(bobSession.lastSeq).toBe(board.seq);

    const bobLeaf = owner.members().find((member) => member.credential.handle === 'bob')!.leafIndex;
    const removedBob = await owner.stageCommit({
      removes: [{ leafIndex: bobLeaf, approvalId: 'apr-remove-bob', signature: signRemove(alice, topicId, 'apr-remove-bob', bob) }],
    });
    await board.post(owner, removedBob, [bobSession, danSession]);
    expect(bobSession.status).toBe('left');
    const quiet = await owner.stageMessage({ type: 'update', body: 'bob is out' });
    await board.post(owner, quiet, [danSession, bobSession]);
    expect(danSession.lastSeq).toBe(board.seq);
    await expect(bobSession.receive(board.seq, quiet.message)).rejects.toMatchObject({ code: 'topic_left' });

    const restarted = reopen(dan, topicId);
    expect(restarted.epoch).toBe(danSession.epoch);
    expect(restarted.lastSeq).toBe(danSession.lastSeq);
    expect(restarted.members().map((member) => member.credential.handle).sort()).toEqual(['alice', 'dan']);
    const again = await owner.stageMessage({ type: 'update', body: 'after restart' });
    await owner.confirmStaged(board.seq + 1);
    const read = await restarted.receive(board.seq + 1, again.message);
    expect(read).toMatchObject({ kind: 'application', authorMatches: true, envelope: { body: 'after restart', author: { handle: 'alice' } } });
  });

  it('hides posting until a joiner accepts, and a gap does not advance state', async () => {
    const bob = makePerson('bob');
    const alice = makePerson('alice');
    const topicId = randomUUID();
    const owner = await TopicSession.create({ store: alice.store, engine: alice.engine, topicId, credential: alice.credential });
    const [keyPackage] = await replenishKeyPackages(bob.engine, bob.credential, bob.store, 1);
    const expiresAt = later();
    const staged = await owner.stageCommit({
      adds: [{ keyPackage: keyPackage!, approvalId: 'apr-bob', expiresAt, signature: signAdd(alice, topicId, 'apr-bob', bob, expiresAt) }],
    });
    await owner.confirmStaged(1);
    const joined = await TopicSession.join({
      store: bob.store,
      engine: bob.engine,
      topicId,
      welcome: staged.welcome!,
      credential: bob.credential,
      ownerIdentityKey: alice.identity.publicKey,
      commitSeq: 1,
    });
    expect(joined.status).toBe('pending_join');
    await expect(joined.stageMessage({ type: 'update', body: 'too soon' })).rejects.toMatchObject({ code: 'topic_pending_join' });
    const decline = await joined.stageMessage({ type: 'leave' });
    expect(decline.kind).toBe('application');
    await joined.abortStaged();
    expect(joined.staged()).toBeUndefined();
    await joined.acceptJoin();
    expect(joined.status).toBe('active');

    await expect(joined.receive(3, decline.message)).rejects.toMatchObject({ code: 'seq_gap' });
    expect(joined.lastSeq).toBe(1);
  });

  it('keeps a staged application generation when another same-epoch message arrives', async () => {
    const bob = makePerson('bob');
    const { owner, session } = await connected([bob]);
    const bobSession = session.get(bob)!;
    const base = owner.lastSeq;
    const first = await owner.stageMessage({ type: 'update', body: 'one' });
    const theirs = await bobSession.stageMessage({ type: 'update', body: 'from bob' });
    await bobSession.confirmStaged(base + 1);
    const bobBefore = bob.engine.deserialize(bob.engine.serialize(bobSession.confirmedState()));

    expect((await owner.receive(base + 1, theirs.message)).kind).toBe('application');
    expect(owner.staged()?.message).toEqual(first.message);
    expect(owner.lastSeq).toBe(base + 1);
    await expect(owner.stageMessage({ type: 'update', body: 'two' })).rejects.toMatchObject({ code: 'outbound_pending' });

    await owner.confirmStaged(base + 2);
    const second = await owner.stageMessage({ type: 'update', body: 'two' });
    const firstRead = await bob.engine.process(bob.engine.deserialize(bob.engine.serialize(bobBefore)), first.message, () => true);
    if (firstRead.kind !== 'application') throw new Error('expected application');
    const secondRead = await bob.engine.process(firstRead.next, second.message, () => true);
    if (secondRead.kind !== 'application') throw new Error('expected application');
    await expect(bob.engine.process(secondRead.next, first.message, () => true)).rejects.toThrow(/past/);
  });

  it('accepts the message after an aborted draft, and does not reuse that generation', async () => {
    const bob = makePerson('bob');
    const { owner, session } = await connected([bob]);
    const bobSession = session.get(bob)!;
    const base = bob.engine.deserialize(bob.engine.serialize(bobSession.confirmedState()));
    const first = await owner.stageMessage({ type: 'update', body: 'one' });
    await owner.abortStaged();
    expect(owner.staged()).toBeUndefined();
    const second = await owner.stageMessage({ type: 'update', body: 'two' });
    await owner.confirmStaged(owner.lastSeq + 1);

    const fromBase = bob.engine.deserialize(bob.engine.serialize(base));
    expect((await bob.engine.process(fromBase, first.message, () => true)).kind).toBe('application');
    const skipped = await bob.engine.process(bob.engine.deserialize(bob.engine.serialize(base)), second.message, () => true);
    expect(skipped.kind).toBe('application');
    if (skipped.kind === 'application') expect(new TextDecoder().decode(skipped.plaintext)).toContain('"two"');
    if (skipped.kind !== 'application') throw new Error('expected application');
    await expect(bob.engine.process(skipped.next, first.message, () => true)).rejects.toThrow(/past/);

    const read = await bobSession.receive(bobSession.lastSeq + 1, second.message);
    expect(read).toMatchObject({ kind: 'application', envelope: { body: 'two' } });
    expect(bobSession.status).toBe('active');

    const past = await bobSession.receive(bobSession.lastSeq + 1, first.message);
    expect(past).toMatchObject({ kind: 'halted', reason: expect.stringMatching(/past/) });
    expect(bobSession.status).toBe('halted');
  });

  it('refuses to discard an application draft past the unpublished cap, and a self-update clears it', async () => {
    const bob = makePerson('bob');
    const { owner, session } = await connected([bob]);
    const bobSession = session.get(bob)!;
    for (let i = 0; i < UNPUBLISHED_GENERATION_SKIP; i++) {
      await owner.stageMessage({ type: 'update', body: `draft ${i}` });
      await owner.abortStaged();
    }
    expect(owner.unpublishedApplication).toBe(UNPUBLISHED_GENERATION_SKIP);
    const atCap = await owner.stageMessage({ type: 'update', body: 'still reachable' });
    await expect(owner.abortStaged()).rejects.toMatchObject({ code: 'self_update_required' });
    expect(owner.staged()?.message).toEqual(atCap.message);
    expect(owner.status).toBe('active');
    expect(owner.unpublishedApplication).toBe(UNPUBLISHED_GENERATION_SKIP);

    await owner.confirmStaged(owner.lastSeq + 1);
    const read = await bobSession.receive(bobSession.lastSeq + 1, atCap.message);
    expect(read).toMatchObject({ kind: 'application', envelope: { body: 'still reachable' } });
    expect(bobSession.status).toBe('active');

    for (let i = 0; i < UNPUBLISHED_GENERATION_SKIP; i++) {
      await owner.stageMessage({ type: 'update', body: `again ${i}` });
      await owner.abortStaged();
    }
    const update = await owner.stageCommit();
    await owner.confirmStaged(owner.lastSeq + 1);
    const committed = await bobSession.receive(bobSession.lastSeq + 1, update.message);
    expect(committed.kind).toBe('commit');
    expect(bobSession.status).toBe('active');
    expect(owner.unpublishedApplication).toBe(0);
    expect(owner.unpublishedHandshake).toBe(0);
    await owner.stageMessage({ type: 'update', body: 'after the epoch' });
    await owner.abortStaged();
    expect(owner.staged()).toBeUndefined();
    expect(owner.status).toBe('active');
  });

  it('refuses to discard a handshake draft past the cap, and the commit at the cap still applies', async () => {
    const bob = makePerson('bob');
    const { owner, session } = await connected([bob]);
    const bobSession = session.get(bob)!;
    const epoch = bobSession.epoch;
    for (let i = 0; i < UNPUBLISHED_GENERATION_SKIP; i++) {
      await owner.stageCommit();
      await owner.abortStaged();
    }
    expect(owner.unpublishedHandshake).toBe(UNPUBLISHED_GENERATION_SKIP);
    const atCap = await owner.stageCommit();
    await expect(owner.abortStaged()).rejects.toMatchObject({ code: 'self_update_required' });
    expect(owner.staged()?.message).toEqual(atCap.message);
    expect(owner.status).toBe('active');
    await owner.confirmStaged(owner.lastSeq + 1);
    const read = await bobSession.receive(bobSession.lastSeq + 1, atCap.message);
    expect(read.kind).toBe('commit');
    expect(bobSession.status).toBe('active');
    expect(bobSession.epoch).toBe(epoch + 1n);
  });

  it('halts when a peer is shown an application generation past the cap', async () => {
    const bob = makePerson('bob');
    const { owner, session } = await connected([bob]);
    const bobSession = session.get(bob)!;
    const before = bob.engine.serialize(bobSession.confirmedState());
    let state = owner.engine.deserialize(owner.engine.serialize(owner.confirmedState()));
    let message: Uint8Array = new Uint8Array();
    for (let i = 0; i < UNPUBLISHED_GENERATION_SKIP + 2; i++) {
      const encrypted = await owner.engine.encrypt(state, new TextEncoder().encode(`{"v":1,"i":${i}}`));
      state = encrypted.next;
      message = encrypted.message;
    }
    const halted = await bobSession.receive(bobSession.lastSeq + 1, message);
    expect(halted).toEqual({ kind: 'halted', reason: 'generation_gap' });
    expect(bobSession.status).toBe('halted');
    expect(bobSession.haltReason).toBe('generation_gap');
    expect(bob.engine.serialize(bobSession.confirmedState())).toEqual(before);
    const again = await bobSession.receive(bobSession.lastSeq + 1, message);
    expect(again).toEqual({ kind: 'halted', reason: 'generation_gap' });
    await expect(bobSession.stageMessage({ type: 'update', body: 'nope' })).rejects.toMatchObject({ code: 'topic_halted' });
  });

  it('halts when a peer is shown a handshake generation past the cap', async () => {
    const bob = makePerson('bob');
    const { owner, session } = await connected([bob]);
    const bobSession = session.get(bob)!;
    const seq = bobSession.lastSeq;
    let state = owner.engine.deserialize(owner.engine.serialize(owner.confirmedState()));
    for (let i = 0; i < UNPUBLISHED_GENERATION_SKIP + 1; i++) {
      state = await owner.engine.discardHandshakeGeneration(state);
    }
    const committed = await owner.engine.commit(state, { authenticatedData: new Uint8Array() });
    const halted = await bobSession.receive(seq + 1, committed.commit);
    expect(halted).toEqual({ kind: 'halted', reason: 'generation_gap' });
    expect(bobSession.status).toBe('halted');
    expect(bobSession.lastSeq).toBe(seq);
  });

  it('remembers the unpublished count across a restart', async () => {
    const bob = makePerson('bob');
    const { alice, topicId, owner } = await connected([bob]);
    for (let i = 0; i < UNPUBLISHED_GENERATION_SKIP; i++) {
      await owner.stageMessage({ type: 'update', body: `draft ${i}` });
      await owner.abortStaged();
    }
    const restarted = reopen(alice, topicId);
    expect(restarted.unpublishedApplication).toBe(UNPUBLISHED_GENERATION_SKIP);
    await restarted.stageMessage({ type: 'update', body: 'held' });
    await expect(restarted.abortStaged()).rejects.toMatchObject({ code: 'self_update_required' });
    expect(restarted.staged()).toBeDefined();
    expect(restarted.status).toBe('active');
  });

  it('does not halt the owner when a joiner aborts a leave and then posts', async () => {
    const bob = makePerson('bob');
    const alice = makePerson('alice');
    const topicId = randomUUID();
    const owner = await TopicSession.create({ store: alice.store, engine: alice.engine, topicId, credential: alice.credential });
    const [keyPackage] = await replenishKeyPackages(bob.engine, bob.credential, bob.store, 1);
    const expiresAt = later();
    const staged = await owner.stageCommit({
      adds: [{ keyPackage: keyPackage!, approvalId: 'apr-bob', expiresAt, signature: signAdd(alice, topicId, 'apr-bob', bob, expiresAt) }],
    });
    await owner.confirmStaged(1);
    const joined = await TopicSession.join({
      store: bob.store,
      engine: bob.engine,
      topicId,
      welcome: staged.welcome!,
      credential: bob.credential,
      ownerIdentityKey: alice.identity.publicKey,
      commitSeq: 1,
    });
    await joined.stageMessage({ type: 'leave' });
    await joined.abortStaged();
    await joined.acceptJoin();
    const update = await joined.stageMessage({ type: 'update', body: 'still here' });
    await joined.confirmStaged(2);
    const read = await owner.receive(2, update.message);
    expect(read).toMatchObject({ kind: 'application', envelope: { body: 'still here' } });
    expect(owner.status).toBe('active');
    expect(joined.status).toBe('active');
  });

  it('burns the handshake generation when a commit is aborted', async () => {
    const bob = makePerson('bob');
    const { owner, session } = await connected([bob]);
    const bobSession = session.get(bob)!;
    const epoch = bobSession.epoch;
    const base = bob.engine.deserialize(bob.engine.serialize(bobSession.confirmedState()));
    const first = await owner.stageCommit();
    await owner.abortStaged();
    const second = await owner.stageCommit();
    expect(second.message).not.toEqual(first.message);

    const applied = await bob.engine.process(bob.engine.deserialize(bob.engine.serialize(base)), second.message, () => true);
    expect(applied.kind).toBe('commit');
    if (applied.kind !== 'commit') throw new Error('expected commit');
    await expect(bob.engine.process(applied.next, first.message, () => true)).rejects.toThrow(/past|epoch/);

    const read = await bobSession.receive(bobSession.lastSeq + 1, second.message);
    expect(read.kind).toBe('commit');
    expect(bobSession.status).toBe('active');
    expect(bobSession.epoch).toBe(epoch + 1n);
  });

  it('halts when the next commit cannot be framed', async () => {
    const bob = makePerson('bob');
    const { owner, session } = await connected([bob]);
    const bobSession = session.get(bob)!;
    const epoch = bobSession.epoch;
    const before = bob.engine.serialize(bobSession.confirmedState());
    const commit = await owner.stageCommit();
    const truncated = commit.message.subarray(0, 3);
    const halted = await bobSession.receive(bobSession.lastSeq + 1, truncated);
    expect(halted).toMatchObject({ kind: 'halted' });
    if (halted.kind === 'halted') expect(halted.reason.length).toBeGreaterThan(0);
    expect(bobSession.status).toBe('halted');
    expect(bobSession.epoch).toBe(epoch);
    expect(bob.engine.serialize(bobSession.confirmedState())).toEqual(before);
    await expect(bobSession.stageMessage({ type: 'update', body: 'after' })).rejects.toMatchObject({ code: 'topic_halted' });
  });

  it('halts on an application message that cannot be decrypted, and refuses a Welcome for another group', async () => {
    const bob = makePerson('bob');
    const { owner, session, topicId } = await connected([bob]);
    const bobSession = session.get(bob)!;
    const epoch = bobSession.epoch;
    const before = bob.engine.serialize(bobSession.confirmedState());
    const good = await owner.stageMessage({ type: 'update', body: 'intact' });
    await owner.confirmStaged(owner.lastSeq + 1);
    const broken = good.message.slice();
    broken[broken.length - 1] = broken[broken.length - 1]! ^ 0xff;
    expect(await bobSession.receive(bobSession.lastSeq + 1, broken)).toMatchObject({ kind: 'halted' });
    expect(bobSession.status).toBe('halted');
    expect(bobSession.epoch).toBe(epoch);
    expect(bob.engine.serialize(bobSession.confirmedState())).toEqual(before);
    await expect(bobSession.stageMessage({ type: 'update', body: 'nope' })).rejects.toMatchObject({ code: 'topic_halted' });
  });

  it('does not consume a KeyPackage when the Welcome belongs to another group', async () => {
    const alice = makePerson('alice');
    const bob = makePerson('bob');
    const [pack] = await replenishKeyPackages(bob.engine, bob.credential, bob.store, 1);
    const stored = bob.store.keyPackages(0).length;
    const state = await alice.engine.createGroup(uuidToBytes(randomUUID()), alice.credential);
    const added = await alice.engine.commit(state, { adds: [pack!], authenticatedData: new Uint8Array() });
    await expect(
      TopicSession.join({
        store: bob.store,
        engine: bob.engine,
        topicId: randomUUID(),
        welcome: added.welcome!,
        credential: bob.credential,
        ownerIdentityKey: alice.identity.publicKey,
        commitSeq: 1,
      }),
    ).rejects.toThrow(/group_id/);
    expect(bob.store.keyPackages(0).length).toBe(stored);
  });
});
