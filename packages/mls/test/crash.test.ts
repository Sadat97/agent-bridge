import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { utf8 } from '@agent-bridge/protocol';
import { replenishKeyPackages, TopicSession } from '../src/index.ts';
import { later, makePerson, reopen, signAdd } from './helpers.ts';

describe('crash safety', () => {
  it('a crash while staging discards the unsent ciphertext, and a crash after staging resends it', async () => {
    const alice = makePerson('alice');
    const bob = makePerson('bob');
    const topicId = randomUUID();
    const aliceSession = await TopicSession.create({
      store: alice.store,
      engine: alice.engine,
      topicId,
      credential: alice.credential,
    });
    const [bobPackage] = await replenishKeyPackages(bob.engine, bob.credential, bob.store, 1);
    const expiresAt = later();
    const added = await aliceSession.stageCommit({
      adds: [{ keyPackage: bobPackage!, approvalId: 'apr-bob', expiresAt, signature: signAdd(alice, topicId, 'apr-bob', bob, expiresAt) }],
    });
    await aliceSession.confirmStaged(1);
    const bobSession = await TopicSession.join({
      store: bob.store,
      engine: bob.engine,
      topicId,
      welcome: added.welcome!,
      credential: bob.credential,
      ownerIdentityKey: alice.identity.publicKey,
      commitSeq: 1,
    });
    await bobSession.acceptJoin();

    alice.store.crashBeforeCommit = true;
    await expect(aliceSession.stageMessage({ type: 'update', body: 'lost' })).rejects.toThrow(/crash before commit/);
    expect(aliceSession.staged()).toBeUndefined();
    expect(aliceSession.lastSeq).toBe(1);
    alice.store.crashBeforeCommit = false;

    const staged = await aliceSession.stageMessage({ type: 'update', body: 'kept' });
    const restarted = reopen(alice, topicId);
    expect(restarted.staged()?.message).toEqual(staged.message);
    expect(restarted.lastSeq).toBe(1);

    restarted.store.crashBeforeCommit = true;
    await expect(restarted.confirmStaged(2)).rejects.toThrow(/crash before commit/);
    expect(restarted.staged()?.message).toEqual(staged.message);
    expect(restarted.lastSeq).toBe(1);
    restarted.store.crashBeforeCommit = false;
    await restarted.confirmStaged(2);

    const read = await bobSession.receive(2, staged.message);
    expect(read).toMatchObject({ kind: 'application', authorMatches: true, envelope: { type: 'update', body: 'kept' } });
  });

  it('a crash mid-receive neither loses nor double-applies the message', async () => {
    const alice = makePerson('alice');
    const bob = makePerson('bob');
    const topicId = randomUUID();
    const aliceSession = await TopicSession.create({
      store: alice.store,
      engine: alice.engine,
      topicId,
      credential: alice.credential,
    });
    const [bobPackage] = await replenishKeyPackages(bob.engine, bob.credential, bob.store, 1);
    const expiresAt = later();
    const added = await aliceSession.stageCommit({
      adds: [{ keyPackage: bobPackage!, approvalId: 'apr-bob', expiresAt, signature: signAdd(alice, topicId, 'apr-bob', bob, expiresAt) }],
    });
    await aliceSession.confirmStaged(1);
    let bobSession = await TopicSession.join({
      store: bob.store,
      engine: bob.engine,
      topicId,
      welcome: added.welcome!,
      credential: bob.credential,
      ownerIdentityKey: alice.identity.publicKey,
      commitSeq: 1,
    });
    await bobSession.acceptJoin();

    const first = await aliceSession.stageMessage({ type: 'update', body: 'one' });
    await aliceSession.confirmStaged(2);
    bob.store.crashBeforeCommit = true;
    await expect(bobSession.receive(2, first.message)).rejects.toThrow(/crash before commit/);
    expect(bobSession.lastSeq).toBe(1);
    expect(bobSession.epoch).toBe(1n);
    bob.store.crashBeforeCommit = false;

    const read = await bobSession.receive(2, first.message);
    expect(read).toMatchObject({ kind: 'application', envelope: { body: 'one' } });
    expect(await bobSession.receive(2, first.message)).toEqual({ kind: 'duplicate' });

    bobSession = reopen(bob, topicId);
    expect(bobSession.lastSeq).toBe(2);
    const second = await aliceSession.stageMessage({ type: 'update', body: 'two' });
    await aliceSession.confirmStaged(3);
    const next = await bobSession.receive(3, second.message);
    expect(next).toMatchObject({ kind: 'application', envelope: { body: 'two' } });
    // The follow-up decrypts, so seq 2 was applied once.
    expect(new TextDecoder().decode(utf8('two'))).toBe('two');
  });
});
