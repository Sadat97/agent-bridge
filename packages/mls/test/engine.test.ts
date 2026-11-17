import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  bytesEqual,
  decodeKeyPackageMessage,
  keyPackageRef,
  utf8,
  uuidToBytes,
} from '@agent-bridge/protocol';
import { generateKeyPackage, createGroup, createCommit, defaultCapabilities, defaultLifetime, encodeMlsMessage, getCiphersuiteFromName, getCiphersuiteImpl } from 'ts-mls';
import { debugClientState } from '../src/ts-mls-engine.ts';
import { replenishKeyPackages } from '../src/index.ts';
import { makePerson } from './helpers.ts';

const accept = () => true;

describe('ts-mls engine', () => {
  it('refuses a credential that is not certified for this device key', async () => {
    const alice = makePerson('alice');
    const other = makePerson('bob');
    await expect(
      alice.engine.generateKeyPackages(1, { ...alice.credential, deviceCert: other.credential.deviceCert }),
    ).rejects.toThrow(/certificate|signature key/i);
  });

  it('creates a group, adds, talks, survives serialize, updates, and removes', async () => {
    const alice = makePerson('alice');
    const bob = makePerson('bob');
    const carol = makePerson('carol');
    const topicId = randomUUID();
    let aliceState = await alice.engine.createGroup(uuidToBytes(topicId), alice.credential);
    expect(alice.engine.epoch(aliceState)).toBe(0n);
    expect(alice.engine.members(aliceState).map((member) => member.credential.handle)).toEqual(['alice']);

    const [bobGenerated] = await bob.engine.generateKeyPackages(1, bob.credential);
    const summary = decodeKeyPackageMessage(bobGenerated!.publicKeyPackage);
    expect(bytesEqual(summary.signatureKey, bob.device.publicKey)).toBe(true);
    expect(keyPackageRef(summary.keyPackage)).toEqual(bobGenerated!.ref);

    const added = await alice.engine.commit(aliceState, {
      adds: [bobGenerated!.publicKeyPackage],
      authenticatedData: utf8('ignored-by-this-test'),
    });
    aliceState = added.pending;
    expect(alice.engine.epoch(aliceState)).toBe(1n);
    expect(added.welcome).toBeDefined();
    let bobState = await bob.engine.join(added.welcome!, bobGenerated!.privateKeyPackage);
    expect(alice.engine.epoch(bobState)).toBe(1n);

    const hello = await alice.engine.encrypt(aliceState, utf8('hello bob'));
    aliceState = hello.next;
    const read = await bob.engine.process(bobState, hello.message, accept);
    if (read.kind !== 'application') throw new Error(`expected application, got ${read.kind}`);
    expect(new TextDecoder().decode(read.plaintext)).toBe('hello bob');
    expect(read.sender.credential.handle).toBe('alice');
    bobState = read.next;

    const reply = await bob.engine.encrypt(bobState, utf8('hello alice'));
    bobState = reply.next;
    const readReply = await alice.engine.process(aliceState, reply.message, accept);
    if (readReply.kind !== 'application') throw new Error(`expected application, got ${readReply.kind}`);
    expect(readReply.sender.credential.handle).toBe('bob');
    aliceState = readReply.next;

    const restored = alice.engine.deserialize(alice.engine.serialize(aliceState));
    expect(alice.engine.epoch(restored)).toBe(alice.engine.epoch(aliceState));
    const after = await alice.engine.encrypt(restored, utf8('after restore'));
    const readAfter = await bob.engine.process(bobState, after.message, accept);
    if (readAfter.kind !== 'application') throw new Error(`expected application, got ${readAfter.kind}`);
    expect(new TextDecoder().decode(readAfter.plaintext)).toBe('after restore');
    bobState = readAfter.next;
    aliceState = after.next;

    const signatureBefore = alice.engine.members(aliceState).find((member) => member.credential.handle === 'bob')!.signatureKey;
    const updated = await bob.engine.commit(bobState, { authenticatedData: new Uint8Array() });
    expect(updated.welcome).toBeUndefined();
    bobState = updated.pending;
    const applied = await alice.engine.process(aliceState, updated.commit, accept);
    if (applied.kind !== 'commit') throw new Error(`expected commit, got ${applied.kind}`);
    expect(applied.committer.credential.handle).toBe('bob');
    expect(alice.engine.epoch(applied.next)).toBe(2n);
    const signatureAfter = alice.engine.members(applied.next).find((member) => member.credential.handle === 'bob')!.signatureKey;
    expect(bytesEqual(signatureBefore, signatureAfter)).toBe(true);
    aliceState = applied.next;

    const [carolPackage] = await carol.engine.generateKeyPackages(1, carol.credential);
    const withCarol = await alice.engine.commit(aliceState, {
      adds: [carolPackage!.publicKeyPackage],
      authenticatedData: new Uint8Array(),
    });
    aliceState = withCarol.pending;
    const carolState = await carol.engine.join(withCarol.welcome!, carolPackage!.privateKeyPackage);
    const bobSeesAdd = await bob.engine.process(bobState, withCarol.commit, accept);
    if (bobSeesAdd.kind !== 'commit') throw new Error(`expected commit, got ${bobSeesAdd.kind}`);
    expect(bobSeesAdd.added[0]?.leafIndex).toBeGreaterThanOrEqual(0);
    expect(bobSeesAdd.added[0]?.credential.handle).toBe('carol');
    bobState = bobSeesAdd.next;

    const bobLeaf = alice.engine.members(aliceState).find((member) => member.credential.handle === 'bob')!.leafIndex;
    const removed = await alice.engine.commit(aliceState, { removes: [bobLeaf], authenticatedData: new Uint8Array() });
    aliceState = removed.pending;
    const bobAfter = await bob.engine.process(bobState, removed.commit, accept);
    if (bobAfter.kind !== 'commit') throw new Error(`expected commit, got ${bobAfter.kind}`);
    const carolAfter = await carol.engine.process(carolState, removed.commit, accept);
    if (carolAfter.kind !== 'commit') throw new Error(`expected commit, got ${carolAfter.kind}`);
    const secret = await alice.engine.encrypt(aliceState, utf8('bob is gone'));
    await expect(bob.engine.process(bobAfter.next, secret.message, accept)).rejects.toThrow();
    const carolStill = await carol.engine.process(carolAfter.next, secret.message, accept);
    if (carolStill.kind !== 'application') throw new Error(`expected application, got ${carolStill.kind}`);
    expect(new TextDecoder().decode(carolStill.plaintext)).toBe('bob is gone');
  });

  it('keeps the previous state usable when a commit is rejected', async () => {
    const alice = makePerson('alice');
    const bob = makePerson('bob');
    const eve = makePerson('eve');
    const topicId = randomUUID();
    let aliceState = await alice.engine.createGroup(uuidToBytes(topicId), alice.credential);
    const [bobPackage] = await replenishKeyPackages(bob.engine, bob.credential, bob.store, 1);
    const added = await alice.engine.commit(aliceState, { adds: [bobPackage!], authenticatedData: new Uint8Array() });
    aliceState = added.pending;
    let bobState = await bob.engine.join(added.welcome!, bob.store.keyPackages(0)[0]!.privatePackage);

    const [evePackage] = await eve.engine.generateKeyPackages(1, eve.credential);
    const copy = alice.engine.deserialize(alice.engine.serialize(aliceState));
    const hidden = await alice.engine.commit(copy, { adds: [evePackage!.publicKeyPackage], authenticatedData: new Uint8Array() });
    const rejected = await bob.engine.process(bobState, hidden.commit, () => false);
    expect(rejected.kind).toBe('rejected');
    expect(bob.engine.epoch(bobState)).toBe(1n);

    const still = await alice.engine.encrypt(aliceState, utf8('still here'));
    const read = await bob.engine.process(bobState, still.message, accept);
    if (read.kind !== 'application') throw new Error(`expected application, got ${read.kind}`);
    expect(new TextDecoder().decode(read.plaintext)).toBe('still here');
  });

  it('rejects a Welcome whose tree fails credential checks', async () => {
    const bob = makePerson('bob');
    const [bobPackage] = await bob.engine.generateKeyPackages(1, bob.credential);
    const impl = await getCiphersuiteImpl(getCiphersuiteFromName('MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519'));
    const bad = await generateKeyPackage(
      { credentialType: 'basic', identity: utf8('not-a-bridge-credential') },
      defaultCapabilities(),
      defaultLifetime,
      [],
      impl,
    );
    const decoded = (await import('ts-mls')).decodeMlsMessage(bobPackage!.publicKeyPackage, 0);
    if (!decoded || decoded[0].wireformat !== 'mls_key_package') throw new Error('key package');
    const group = await createGroup(uuidToBytes(randomUUID()), bad.publicPackage, bad.privatePackage, [], impl);
    const commit = await createCommit(
      { state: group, cipherSuite: impl },
      { extraProposals: [{ proposalType: 'add', add: { keyPackage: decoded[0].keyPackage } }], ratchetTreeExtension: true },
    );
    const welcome = encodeMlsMessage({ welcome: commit.welcome!, wireformat: 'mls_welcome', version: 'mls10' });
    await expect(bob.engine.join(welcome, bobPackage!.privateKeyPackage)).rejects.toThrow(/credential/i);
  });

  it('rejects a Welcome when a member handle is pinned to a different identity key', async () => {
    const alice = makePerson('alice');
    const bob = makePerson('bob');
    const topicId = randomUUID();
    const aliceState = await alice.engine.createGroup(uuidToBytes(topicId), alice.credential);
    const [bobPackage] = await bob.engine.generateKeyPackages(1, bob.credential);
    const added = await alice.engine.commit(aliceState, { adds: [bobPackage!.publicKeyPackage], authenticatedData: new Uint8Array() });
    bob.store.pins.set(alice.handle, makePerson('mallory').identity.publicKey);
    const pinned = (await import('../src/index.ts')).createTsMlsEngine({
      devicePrivateKey: bob.device.privateKey,
      pins: bob.store.pins,
    });
    await expect(pinned.join(added.welcome!, bobPackage!.privateKeyPackage)).rejects.toThrow(/credential/i);
  });

  it('does not persist previous-epoch secrets', async () => {
    const alice = makePerson('alice');
    const topicId = randomUUID();
    let state = await alice.engine.createGroup(uuidToBytes(topicId), alice.credential);
    const oldSecret = debugClientState(state).secretTree[0]?.application.secret;
    if (!oldSecret) throw new Error('missing epoch secret');
    const updated = await alice.engine.commit(state, { authenticatedData: new Uint8Array() });
    state = updated.pending;
    const again = await alice.engine.commit(state, { authenticatedData: new Uint8Array() });
    const bytes = alice.engine.serialize(again.pending);
    expect(Buffer.from(bytes).includes(Buffer.from(oldSecret))).toBe(false);
    const restored = debugClientState(alice.engine.deserialize(bytes));
    expect(restored.historicalReceiverData.size).toBe(0);
    for (const node of restored.secretTree) {
      if (!node) continue;
      expect(Object.keys(node.application.unusedGenerations)).toEqual([]);
      expect(Object.keys(node.handshake.unusedGenerations)).toEqual([]);
    }
  });
});
