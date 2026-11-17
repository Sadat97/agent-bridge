import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createCommit, createGroup, createProposal, encodeMlsMessage } from 'ts-mls';
import { toBase64, uuidToBytes } from '@agent-bridge/protocol';
import { appMessage, commit, impl, Person, startRelay } from './helpers.ts';
import type { TestRelay } from './helpers.ts';

let relay: TestRelay;
let alice: Person;
let outsider: Person;
beforeAll(async () => {
  relay = await startRelay();
  alice = await Person.create(relay, 'alice');
  outsider = await Person.create(relay, 'outsider');
});
afterAll(() => relay.close());

describe('topics', () => {
  it('creates a topic with the caller as topic owner', async () => {
    const { topicId } = await alice.createTopic();
    const res = await alice.call('GET', `/v1/topics/${topicId}`);
    expect(res.body).toMatchObject({
      topic_id: topicId,
      owner: 'alice',
      role: 'owner',
      epoch: 0,
      last_seq: 0,
      min_seq: 1,
      closed_at: null,
      members: [{ device_id: alice.deviceId, handle: 'alice', role: 'owner', joined_epoch: 0, stale: false }],
    });
    expect((await alice.call('GET', '/v1/topics')).body.topics.map((t: any) => t.topic_id)).toContain(topicId);
    expect(await alice.call('POST', '/v1/topics', { id: topicId })).toMatchObject({ status: 409, body: { error: 'topic_exists' } });
  });

  it('hides topics from non-members', async () => {
    const { topicId, group } = await alice.createTopic();
    expect((await outsider.call('GET', `/v1/topics/${topicId}`)).status).toBe(404);
    expect((await outsider.call('GET', `/v1/topics/${topicId}/messages`)).status).toBe(404);
    const { message } = await appMessage(group, 'hi');
    expect((await outsider.call('POST', `/v1/topics/${topicId}/messages`, { message })).status).toBe(404);
    expect((await outsider.call('GET', '/v1/topics')).body.topics).toEqual([]);
  });
});

describe('sequencing', () => {
  it('assigns contiguous per-topic sequence numbers', async () => {
    let { topicId, group } = await alice.createTopic();
    const other = await alice.createTopic();
    for (let i = 1; i <= 3; i++) {
      const sent = await appMessage(group, `m${i}`);
      group = sent.group;
      const res = await alice.call('POST', `/v1/topics/${topicId}/messages`, { message: sent.message });
      expect(res).toMatchObject({ status: 201, body: { seq: i, epoch: 0 } });
      // Another topic's traffic does not affect this topic's numbering.
      const elsewhere = await appMessage(other.group, 'x');
      other.group = elsewhere.group;
      await alice.call('POST', `/v1/topics/${other.topicId}/messages`, { message: elsewhere.message });
    }

    const page1 = await alice.call('GET', `/v1/topics/${topicId}/messages?limit=2`);
    expect(page1.body.messages.map((m: any) => m.seq)).toEqual([1, 2]);
    expect(page1.body.last_seq).toBe(3);
    expect(page1.body.messages[0]).toMatchObject({ epoch: 0, content: 'application', sender_device: alice.deviceId });
    const page2 = await alice.call('GET', `/v1/topics/${topicId}/messages?after_seq=2`);
    expect(page2.body.messages.map((m: any) => m.seq)).toEqual([3]);
  });

  it('accepts exactly one of two concurrent commits from the same epoch', async () => {
    const { topicId, group } = await alice.createTopic();
    const a = await commit(group);
    const b = await commit(group);

    const results = await Promise.all([
      alice.call('POST', `/v1/topics/${topicId}/messages`, { message: a.message }),
      alice.call('POST', `/v1/topics/${topicId}/messages`, { message: b.message }),
    ]);
    const statuses = results.map((r) => r.status).sort();
    expect(statuses).toEqual([201, 409]);
    const loser = results.find((r) => r.status === 409)!;
    expect(loser.body).toMatchObject({ error: 'stale_epoch', details: { current_epoch: 1 } });
    const winner = results[0]!.status === 201 ? a : b;

    // The group moved on: anything still at epoch 0 is rejected...
    const late = await appMessage(group, 'too late');
    expect((await alice.call('POST', `/v1/topics/${topicId}/messages`, { message: late.message })).body.error).toBe('stale_epoch');
    // ...and the winner's epoch is accepted.
    const next = await appMessage(winner.group, 'on time');
    expect(await alice.call('POST', `/v1/topics/${topicId}/messages`, { message: next.message })).toMatchObject({
      status: 201,
      body: { seq: 2, epoch: 1 },
    });
    expect((await alice.call('GET', `/v1/topics/${topicId}`)).body).toMatchObject({ epoch: 1, last_seq: 2 });
  });

  it('serializes many concurrent writers without gaps', async () => {
    const { topicId, group } = await alice.createTopic();
    // Ten application messages from the same epoch, all valid, posted at once.
    let state = group;
    const messages: string[] = [];
    for (let i = 0; i < 10; i++) {
      const sent = await appMessage(state, `burst ${i}`);
      state = sent.group;
      messages.push(sent.message);
    }
    const results = await Promise.all(messages.map((message) => alice.call('POST', `/v1/topics/${topicId}/messages`, { message })));
    expect(results.every((r) => r.status === 201)).toBe(true);
    expect(results.map((r) => r.body.seq).sort((x, y) => x - y)).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
  });
});

describe('MLS message validation', () => {
  it('rejects input that is not an MLS PrivateMessage for this topic', async () => {
    const { topicId, group } = await alice.createTopic();
    const post = (body: unknown) => alice.call('POST', `/v1/topics/${topicId}/messages`, body);

    expect((await post({ message: 'not base64!' })).body.error).toBe('invalid_base64');
    expect((await post({ message: toBase64(new Uint8Array([0, 1, 0, 2, 9])) })).body.error).toBe('invalid_mls_message');

    // A message for a different group.
    const otherKp = await alice.newKeyPackage();
    const otherGroup = await createGroup(uuidToBytes(randomUUID()), otherKp.publicPackage, otherKp.privatePackage, [], impl);
    expect((await post({ message: (await appMessage(otherGroup, 'x')).message })).body.error).toBe('group_mismatch');

    // A PublicMessage commit.
    const pub = await createCommit({ state: group, cipherSuite: impl }, { wireAsPublicMessage: true });
    expect((await post({ message: toBase64(encodeMlsMessage(pub.commit)) })).body.error).toBe('unsupported_wire_format');

    // A standalone proposal.
    const proposal = await createProposal(group, false, { proposalType: 'remove', remove: { removed: 0 } }, impl);
    expect((await post({ message: toBase64(encodeMlsMessage(proposal.message)) })).body.error).toBe('proposals_not_supported');

    // Membership data on an application message.
    const app = await appMessage(group, 'x');
    expect((await post({ message: app.message, membership: { adds: [] } })).body.error).toBe('membership_requires_commit');
  });

  it('enforces the message size limit', async () => {
    const small = await startRelay({ maxMessageBytes: 512 });
    try {
      const owner = await Person.create(small, 'owner');
      const { topicId, group } = await owner.createTopic();
      const big = await appMessage(group, 'x'.repeat(2000));
      const res = await owner.call('POST', `/v1/topics/${topicId}/messages`, { message: big.message });
      expect(res.status).toBe(400); // rejected by the schema before decoding
      const ok = await appMessage(group, 'small');
      expect((await owner.call('POST', `/v1/topics/${topicId}/messages`, { message: ok.message })).status).toBe(201);
    } finally {
      await small.close();
    }
  });
});

describe('closing', () => {
  it('lets only the topic owner close, then rejects new messages', async () => {
    const { topicId, group } = await alice.createTopic();
    const closed = await alice.call('POST', `/v1/topics/${topicId}/close`);
    expect(closed.status).toBe(200);
    const msg = await appMessage(group, 'after close');
    expect((await alice.call('POST', `/v1/topics/${topicId}/messages`, { message: msg.message })).body.error).toBe('topic_closed');
    expect((await alice.call('GET', `/v1/topics/${topicId}`)).body.closed_at).toBe(closed.body.closed_at);
  });
});
