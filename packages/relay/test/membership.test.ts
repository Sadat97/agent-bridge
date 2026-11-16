import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { ClientState, Proposal } from 'ts-mls';
import { bytesEqual } from '@agent-bridge/protocol';
import { appMessage, applyCommit, commit, decodeKeyPackage, nowSeconds, Person, readApp, startRelay } from './helpers.ts';
import type { TestRelay } from './helpers.ts';

let relay: TestRelay;
beforeAll(async () => {
  relay = await startRelay();
});
afterAll(() => relay.close());

function leafIndexOf(group: ClientState, person: Person): number {
  const index = group.ratchetTree.findIndex(
    (node, i) => i % 2 === 0 && node?.nodeType === 'leaf' && bytesEqual(node.leaf.signaturePublicKey, person.device.publicKey),
  );
  if (index < 0) throw new Error(`${person.handle} is not in the group`);
  return index / 2;
}

/** Topic owner adds `invitee`: claim a KeyPackage, commit the Add with its approval, post. */
async function addMember(owner: Person, topicId: string, group: ClientState, invitee: Person, approvalId: string) {
  const expiresAt = nowSeconds() + 3600;
  const approval = owner.signAdd(topicId, approvalId, invitee, expiresAt);
  const claim = await owner.call('POST', `/v1/devices/${invitee.deviceId}/key-packages/claim`, {
    topic_id: topicId,
    approval_id: approvalId,
    expires_at: expiresAt,
    approval,
  });
  if (claim.status !== 200) throw new Error(`claim failed: ${JSON.stringify(claim.body)}`);
  const add: Proposal = { proposalType: 'add', add: { keyPackage: decodeKeyPackage(claim.body.key_package) } };
  const committed = await commit(group, [add]);
  const res = await owner.call('POST', `/v1/topics/${topicId}/messages`, {
    message: committed.message,
    membership: { adds: [{ device_id: invitee.deviceId, approval_id: approvalId, expires_at: expiresAt, approval }] },
    welcome: { message: committed.welcome, recipients: [invitee.deviceId] },
  });
  return { res, group: committed.group, committed, approval, expiresAt };
}

describe('KeyPackages', () => {
  it('accepts only KeyPackages signed with the uploading device key', async () => {
    const owner = await Person.create(relay, 'kp-owner');
    const other = await Person.create(relay, 'kp-other');
    expect(await owner.uploadKeyPackages(3)).toMatchObject({ status: 200, body: { accepted: 3, unclaimed: 3 } });

    const foreign = await other.newKeyPackage();
    const res = await owner.call('POST', '/v1/key-packages', { key_packages: [foreign.encoded] });
    expect(res.body.error).toBe('key_package_not_yours');

    // Re-uploading the same KeyPackage is a no-op.
    const kp = await owner.newKeyPackage();
    await owner.call('POST', '/v1/key-packages', { key_packages: [kp.encoded] });
    expect((await owner.call('POST', '/v1/key-packages', { key_packages: [kp.encoded] })).body).toEqual({ accepted: 0, unclaimed: 4 });
    expect((await owner.call('GET', '/v1/key-packages/count')).body).toEqual({ unclaimed: 4 });
  });

  it('lets only the topic owner claim, with a valid approval, idempotently', async () => {
    const alice = await Person.create(relay, 'claim-alice');
    const bob = await Person.create(relay, 'claim-bob');
    const carol = await Person.create(relay, 'claim-carol');
    await bob.uploadKeyPackages(2);
    const { topicId } = await alice.createTopic();
    const expiresAt = nowSeconds() + 3600;
    const claim = (who: Person, body: Record<string, unknown>) =>
      who.call('POST', `/v1/devices/${bob.deviceId}/key-packages/claim`, {
        topic_id: topicId,
        approval_id: 'apr-claim',
        expires_at: expiresAt,
        approval: alice.signAdd(topicId, 'apr-claim', bob, expiresAt),
        ...body,
      });

    expect((await claim(carol, {})).status).toBe(404); // not in the topic
    expect((await claim(alice, { approval: carol.signAdd(topicId, 'apr-claim', bob, expiresAt) })).body.error).toBe('invalid_approval');
    expect((await claim(alice, { expires_at: expiresAt + 1 })).body.error).toBe('invalid_approval'); // field bound by signature
    const stale = nowSeconds() - 10;
    expect(
      (await claim(alice, { expires_at: stale, approval: alice.signAdd(topicId, 'apr-claim', bob, stale) })).body.error,
    ).toBe('approval_expired');

    const first = await claim(alice, {});
    expect(first.status).toBe(200);
    expect((await claim(alice, {})).body.key_package).toBe(first.body.key_package);
    expect((await bob.call('GET', '/v1/key-packages/count')).body.unclaimed).toBe(1);
  });

  it('reports when a device has no KeyPackages left', async () => {
    const alice = await Person.create(relay, 'empty-alice');
    const bob = await Person.create(relay, 'empty-bob');
    const { topicId } = await alice.createTopic();
    const expiresAt = nowSeconds() + 3600;
    const res = await alice.call('POST', `/v1/devices/${bob.deviceId}/key-packages/claim`, {
      topic_id: topicId,
      approval_id: 'apr-empty',
      expires_at: expiresAt,
      approval: alice.signAdd(topicId, 'apr-empty', bob, expiresAt),
    });
    expect(res).toMatchObject({ status: 404, body: { error: 'no_key_package' } });
  });
});

describe('add, join, talk', () => {
  it('delivers a Welcome and lets the new member read messages from its epoch on', async () => {
    const alice = await Person.create(relay, 'trip-alice');
    const bob = await Person.create(relay, 'trip-bob');
    await bob.uploadKeyPackages(1);
    let { topicId, group } = await alice.createTopic();

    // Something said before Bob joins.
    const before = await appMessage(group, 'before bob');
    group = before.group;
    await alice.call('POST', `/v1/topics/${topicId}/messages`, { message: before.message });

    const added = await addMember(alice, topicId, group, bob, 'apr-bob');
    expect(added.res).toMatchObject({ status: 201, body: { seq: 2, epoch: 1 } });
    group = added.group;

    const topic = await alice.call('GET', `/v1/topics/${topicId}`);
    expect(topic.body.members.map((m: any) => [m.handle, m.role, m.joined_epoch])).toEqual([
      ['trip-alice', 'owner', 0],
      ['trip-bob', 'member', 1],
    ]);

    // Bob finds the Welcome, joins, and acknowledges it.
    const inbox = await bob.call('GET', '/v1/inbox');
    expect(inbox.body.welcomes).toHaveLength(1);
    expect(inbox.body.welcomes[0]).toMatchObject({ topic_id: topicId, commit_seq: 2 });
    let bobGroup = await bob.join(inbox.body.welcomes[0].welcome);
    expect((await bob.call('POST', `/v1/inbox/${inbox.body.welcomes[0].id}/ack`)).status).toBe(200);
    expect((await bob.call('GET', '/v1/inbox')).body.welcomes).toEqual([]);

    // Alice speaks in the new epoch; Bob fetches from the start and sees only post-join messages.
    const hello = await appMessage(group, 'hello bob');
    group = hello.group;
    expect((await alice.call('POST', `/v1/topics/${topicId}/messages`, { message: hello.message })).body).toEqual({ seq: 3, epoch: 1 });
    const fetched = await bob.call('GET', `/v1/topics/${topicId}/messages?after_seq=0`);
    expect(fetched.body.messages.map((m: any) => m.seq)).toEqual([3]);
    const read = await readApp(bobGroup, fetched.body.messages[0].message);
    expect(read.text).toBe('hello bob');
    bobGroup = read.group;

    // Bob replies; Alice decrypts.
    const reply = await appMessage(bobGroup, 'hi alice');
    bobGroup = reply.group;
    expect((await bob.call('POST', `/v1/topics/${topicId}/messages`, { message: reply.message })).status).toBe(201);
    const forAlice = await alice.call('GET', `/v1/topics/${topicId}/messages?after_seq=3`);
    expect((await readApp(group, forAlice.body.messages[0].message)).text).toBe('hi alice');

    // A member may rotate its own keys with an empty commit, but not change membership.
    const update = await commit(bobGroup);
    expect((await bob.call('POST', `/v1/topics/${topicId}/messages`, { message: update.message })).body).toEqual({ seq: 5, epoch: 2 });
    group = await applyCommit(group, (await alice.call('GET', `/v1/topics/${topicId}/messages?after_seq=4`)).body.messages[0].message);
    expect(group.groupContext.epoch).toBe(2n);
  });

  it('rejects membership changes that are not approved by the topic owner', async () => {
    const alice = await Person.create(relay, 'guard-alice');
    const bob = await Person.create(relay, 'guard-bob');
    const carol = await Person.create(relay, 'guard-carol');
    await bob.uploadKeyPackages(1);
    await carol.uploadKeyPackages(2);
    let { topicId, group } = await alice.createTopic();
    const added = await addMember(alice, topicId, group, bob, 'apr-1');
    expect(added.res.status).toBe(201);
    group = added.group;
    const bobGroup = await bob.join((await bob.call('GET', '/v1/inbox')).body.welcomes[0].welcome);
    const post = (who: Person, body: unknown) => who.call('POST', `/v1/topics/${topicId}/messages`, body);
    const expiresAt = nowSeconds() + 3600;

    // Bob (a member, not the topic owner) tries to add Carol.
    const carolKp = await carol.newKeyPackage();
    const bobAdds = await commit(bobGroup, [{ proposalType: 'add', add: { keyPackage: carolKp.publicPackage } }]);
    const asBob = await post(bob, {
      message: bobAdds.message,
      membership: { adds: [{ device_id: carol.deviceId, approval_id: 'apr-2', expires_at: expiresAt, approval: bob.signAdd(topicId, 'apr-2', carol, expiresAt) }] },
      welcome: { message: bobAdds.welcome, recipients: [carol.deviceId] },
    });
    expect(asBob).toMatchObject({ status: 403, body: { error: 'not_topic_owner' } });

    // Alice, with an approval signed by someone else.
    const aliceAdds = await commit(group, [{ proposalType: 'add', add: { keyPackage: carolKp.publicPackage } }]);
    const forged = await post(alice, {
      message: aliceAdds.message,
      membership: { adds: [{ device_id: carol.deviceId, approval_id: 'apr-2', expires_at: expiresAt, approval: bob.signAdd(topicId, 'apr-2', carol, expiresAt) }] },
      welcome: { message: aliceAdds.welcome, recipients: [carol.deviceId] },
    });
    expect(forged).toMatchObject({ status: 403, body: { error: 'invalid_approval' } });

    // Re-using an approval id that already added Bob.
    const reused = await post(alice, {
      message: aliceAdds.message,
      membership: { adds: [{ device_id: carol.deviceId, approval_id: 'apr-1', expires_at: expiresAt, approval: alice.signAdd(topicId, 'apr-1', carol, expiresAt) }] },
      welcome: { message: aliceAdds.welcome, recipients: [carol.deviceId] },
    });
    expect(reused).toMatchObject({ status: 409, body: { error: 'approval_used' } });

    // A Welcome that is not addressed to exactly the added devices.
    const mismatched = await post(alice, {
      message: aliceAdds.message,
      membership: { adds: [{ device_id: carol.deviceId, approval_id: 'apr-3', expires_at: expiresAt, approval: alice.signAdd(topicId, 'apr-3', carol, expiresAt) }] },
      welcome: { message: aliceAdds.welcome, recipients: [bob.deviceId] },
    });
    expect(mismatched.body.error).toBe('welcome_mismatch');

    // Adding someone who is already a member.
    const again = await post(alice, {
      message: aliceAdds.message,
      membership: { adds: [{ device_id: bob.deviceId, approval_id: 'apr-4', expires_at: expiresAt, approval: alice.signAdd(topicId, 'apr-4', bob, expiresAt) }] },
      welcome: { message: aliceAdds.welcome, recipients: [bob.deviceId] },
    });
    expect(again).toMatchObject({ status: 409, body: { error: 'already_member' } });

    // None of the rejected commits advanced the epoch.
    expect((await alice.call('GET', `/v1/topics/${topicId}`)).body).toMatchObject({ epoch: 1, last_seq: 1 });
  });
});

describe('what the relay cannot see (bridges must enforce DESIGN.md 5.8)', () => {
  // Pins a known limitation. Commits are encrypted, so the relay only checks the
  // membership changes the sender *declares*. A member can hide an Add inside a
  // commit, declare nothing, and the relay sequences it like a key update.
  // Every bridge must decrypt the commit, find the unapproved Add, and halt.
  it('accepts a member commit that secretly adds someone without declaring it', async () => {
    const alice = await Person.create(relay, 'hidden-alice');
    const bob = await Person.create(relay, 'hidden-bob');
    const eve = await Person.create(relay, 'hidden-eve');
    await bob.uploadKeyPackages(1);
    let { topicId, group } = await alice.createTopic();
    group = (await addMember(alice, topicId, group, bob, 'apr-bob')).group;
    const bobGroup = await bob.join((await bob.call('GET', '/v1/inbox')).body.welcomes[0].welcome);

    // Eve hands Bob a KeyPackage out of band; Bob commits an Add for her and declares nothing.
    const eveKp = await eve.newKeyPackage();
    const sneaky = await commit(bobGroup, [{ proposalType: 'add', add: { keyPackage: eveKp.publicPackage } }]);
    const res = await bob.call('POST', `/v1/topics/${topicId}/messages`, { message: sneaky.message });
    expect(res).toMatchObject({ status: 201, body: { epoch: 2 } });

    // The relay's own records still show only Alice and Bob, and Eve cannot fetch...
    expect((await alice.call('GET', `/v1/topics/${topicId}`)).body.members.map((m: any) => m.handle)).toEqual([
      'hidden-alice',
      'hidden-bob',
    ]);
    expect((await eve.call('GET', `/v1/topics/${topicId}/messages`)).status).toBe(404);
    // ...but in the MLS group Eve is now a member. Only the bridges can see this.
    const eveGroup = await eve.join(sneaky.welcome!);
    expect(eveGroup.groupContext.epoch).toBe(2n);
  });
});

describe('remove and leave', () => {
  it('removes a member with the topic owner approval, and honours a leave', async () => {
    const alice = await Person.create(relay, 'rm-alice');
    const bob = await Person.create(relay, 'rm-bob');
    const carol = await Person.create(relay, 'rm-carol');
    await bob.uploadKeyPackages(1);
    await carol.uploadKeyPackages(1);
    let { topicId, group } = await alice.createTopic();
    let step = await addMember(alice, topicId, group, bob, 'apr-bob');
    group = step.group;
    step = await addMember(alice, topicId, group, carol, 'apr-carol');
    group = step.group;
    let carolGroup = await carol.join((await carol.call('GET', '/v1/inbox')).body.welcomes[0].welcome);
    const post = (who: Person, body: unknown) => who.call('POST', `/v1/topics/${topicId}/messages`, body);

    const removeBob = await commit(group, [{ proposalType: 'remove', remove: { removed: leafIndexOf(group, bob) } }]);

    // The relay cannot see inside the commit; it checks the declared delta. The topic owner
    // cannot be removed, a remove needs an approval or a leave, and approvals bind the device.
    const tryRemove = (removes: unknown) => post(alice, { message: removeBob.message, membership: { removes } });
    expect((await tryRemove([{ device_id: alice.deviceId, approval_id: 'x', approval: alice.signRemove(topicId, 'x', alice) }])).body.error).toBe('cannot_remove_owner');
    expect((await tryRemove([{ device_id: bob.deviceId, approval_id: 'x' }])).body.error).toBe('invalid_remove');
    expect((await tryRemove([{ device_id: bob.deviceId, approval_id: 'x', approval: alice.signRemove(topicId, 'x', carol) }])).body.error).toBe('invalid_approval');

    // Remove Bob with an approval.
    const removed = await post(alice, {
      message: removeBob.message,
      membership: { removes: [{ device_id: bob.deviceId, approval_id: 'apr-rm-bob', approval: alice.signRemove(topicId, 'apr-rm-bob', bob) }] },
    });
    expect(removed).toMatchObject({ status: 201, body: { epoch: 3 } });
    group = removeBob.group;
    expect((await bob.call('GET', `/v1/topics/${topicId}/messages`)).status).toBe(404);
    expect((await alice.call('GET', `/v1/topics/${topicId}`)).body.members.map((m: any) => m.handle)).toEqual(['rm-alice', 'rm-carol']);

    // Carol catches up, then announces she is leaving.
    const carolView = await carol.call('GET', `/v1/topics/${topicId}/messages`);
    carolGroup = await applyCommit(carolGroup, carolView.body.messages.at(-1).message);
    const leave = await appMessage(carolGroup, '{"type":"leave"}');
    const leaveSeq = (await post(carol, { message: leave.message })).body.seq;
    const aliceMsg = await appMessage(group, 'noted');
    group = aliceMsg.group;
    const aliceSeq = (await post(alice, { message: aliceMsg.message })).body.seq;

    const removeCarol = await commit(group, [{ proposalType: 'remove', remove: { removed: leafIndexOf(group, carol) } }]);
    // leave_seq must point at a message Carol sent.
    expect(
      (await post(alice, { message: removeCarol.message, membership: { removes: [{ device_id: carol.deviceId, approval_id: 'leave-carol', leave_seq: aliceSeq }] } })).body.error,
    ).toBe('invalid_leave');
    const left = await post(alice, {
      message: removeCarol.message,
      membership: { removes: [{ device_id: carol.deviceId, approval_id: 'leave-carol', leave_seq: leaveSeq }] },
    });
    expect(left.status).toBe(201);

    const changes = await relay.pool.query(
      'SELECT device_id, change FROM membership_changes WHERE topic_id = $1 ORDER BY commit_seq',
      [topicId],
    );
    expect(changes.rows.map((r) => r.change)).toEqual(['add', 'add', 'remove', 'leave']);
  });
});
