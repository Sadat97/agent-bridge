import { describe, expect, it } from 'vitest';
import { replenishKeyPackages, TopicSession } from '../src/index.ts';
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
    const topicId = (await import('node:crypto')).randomUUID();
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
    await joined.acceptJoin();
    expect(joined.status).toBe('active');

    await expect(joined.receive(3, decline.message)).rejects.toMatchObject({ code: 'seq_gap' });
    expect(joined.lastSeq).toBe(1);
  });
});
