import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import WebSocket from 'ws';
import type { ClientState, Proposal } from 'ts-mls';
import { runRetention } from '../src/app.ts';
import { appMessage, commit, connectEvents, decodeKeyPackage, nowSeconds, Person, readApp, startRelay } from './helpers.ts';
import type { TestRelay } from './helpers.ts';

let relay: TestRelay;
beforeAll(async () => {
  relay = await startRelay();
});
afterAll(() => relay.close());

async function addMember(owner: Person, topicId: string, group: ClientState, invitee: Person, approvalId: string) {
  const expiresAt = nowSeconds() + 3600;
  const approval = owner.signAdd(topicId, approvalId, invitee, expiresAt);
  const claim = await owner.call('POST', `/v1/devices/${invitee.deviceId}/key-packages/claim`, {
    topic_id: topicId,
    approval_id: approvalId,
    expires_at: expiresAt,
    approval,
  });
  const add: Proposal = { proposalType: 'add', add: { keyPackage: decodeKeyPackage(claim.body.key_package) } };
  const committed = await commit(group, [add]);
  const res = await owner.call('POST', `/v1/topics/${topicId}/messages`, {
    message: committed.message,
    membership: { adds: [{ device_id: invitee.deviceId, approval_id: approvalId, expires_at: expiresAt, approval }] },
    welcome: { message: committed.welcome, recipients: [invitee.deviceId] },
  });
  if (res.status !== 201) throw new Error(`add failed: ${JSON.stringify(res.body)}`);
  return committed.group;
}

async function memberCursor(topicId: string, person: Person): Promise<{ last_fetched_seq: number; stale_at: Date | null }> {
  const { rows } = await relay.pool.query(
    'SELECT last_fetched_seq, stale_at FROM topic_members WHERE topic_id = $1 AND device_id = $2',
    [topicId, person.deviceId],
  );
  return rows[0];
}

describe('WebSocket events', () => {
  it('refuses connections without a valid token', async () => {
    const socket = new WebSocket(relay.baseUrl.replace('http', 'ws') + '/v1/ws');
    const status = await new Promise((resolve) => socket.once('unexpected-response', (_req, res) => resolve(res.statusCode)));
    expect(status).toBe(401);
  });

  it('pushes messages, Welcomes, and low-KeyPackage warnings to the right devices', async () => {
    const alice = await Person.create(relay, 'ws-alice');
    const bob = await Person.create(relay, 'ws-bob');
    const carol = await Person.create(relay, 'ws-carol');
    await bob.uploadKeyPackages(1);
    await carol.uploadKeyPackages(1);
    const aliceEvents = await connectEvents(alice);
    const bobEvents = await connectEvents(bob);
    const carolEvents = await connectEvents(carol);

    let { topicId, group } = await alice.createTopic();
    group = await addMember(alice, topicId, group, bob, 'apr-bob');

    // Bob gets his Welcome, plus a warning that his KeyPackages are running low.
    const welcome = await bobEvents.next((e) => e.type === 'welcome');
    expect(welcome).toMatchObject({ topic_id: topicId, commit_seq: 1 });
    expect(await bobEvents.next((e) => e.type === 'key_packages_low')).toEqual({ type: 'key_packages_low', count: 0 });
    let bobGroup = await bob.join((await bob.call('GET', '/v1/inbox')).body.welcomes[0].welcome);
    // Bob was added by that commit, so he is not sent the commit itself.
    expect(bobEvents.events.some((e) => e.type === 'message')).toBe(false);

    // An application message reaches both members inline, and Bob can decrypt it.
    const hello = await appMessage(group, 'pushed to bob');
    group = hello.group;
    await alice.call('POST', `/v1/topics/${topicId}/messages`, { message: hello.message });
    const pushed = await bobEvents.next((e) => e.type === 'message' && e.seq === 2);
    expect(pushed).toMatchObject({ topic_id: topicId, epoch: 1, content: 'application', sender_device: alice.deviceId });
    const read = await readApp(bobGroup, pushed.message);
    expect(read.text).toBe('pushed to bob');
    bobGroup = read.group;
    await aliceEvents.next((e) => e.type === 'message' && e.seq === 2);

    // Carol is not a member and hears nothing about this topic.
    expect(carolEvents.events.filter((e) => e.topic_id === topicId)).toEqual([]);

    aliceEvents.close();
    bobEvents.close();
    carolEvents.close();
  });

  it('answers pings and advances the cursor on ack, bounded by the topic', async () => {
    const alice = await Person.create(relay, 'ack-alice');
    const bob = await Person.create(relay, 'ack-bob');
    await bob.uploadKeyPackages(1);
    let { topicId, group } = await alice.createTopic();
    group = await addMember(alice, topicId, group, bob, 'apr');
    for (const text of ['one', 'two']) {
      const sent = await appMessage(group, text);
      group = sent.group;
      await alice.call('POST', `/v1/topics/${topicId}/messages`, { message: sent.message });
    }
    expect((await memberCursor(topicId, bob)).last_fetched_seq).toBe(1); // joined at seq 1

    const events = await connectEvents(bob);
    events.socket.send(JSON.stringify({ type: 'ping' }));
    await events.next((e) => e.type === 'pong');
    events.socket.send(JSON.stringify({ type: 'ack', topic_id: topicId, seq: 999 }));
    events.socket.send(JSON.stringify({ type: 'ping' }));
    await events.next((e) => e.type === 'pong' && events.events.filter((x) => x.type === 'pong').length === 2);
    expect((await memberCursor(topicId, bob)).last_fetched_seq).toBe(3); // capped at last_seq
    events.socket.send('not json');
    expect(await events.next((e) => e.type === 'error')).toEqual({ type: 'error', error: 'invalid_json' });
    events.close();
  });
});

describe('retention', () => {
  it('prunes old ciphertext, marks members who missed it as stale, and tells the topic owner', async () => {
    const alice = await Person.create(relay, 'ret-alice');
    const bob = await Person.create(relay, 'ret-bob');
    const carol = await Person.create(relay, 'ret-carol');
    await bob.uploadKeyPackages(1);
    await carol.uploadKeyPackages(1);
    let { topicId, group } = await alice.createTopic();
    group = await addMember(alice, topicId, group, bob, 'apr-bob'); // seq 1
    group = await addMember(alice, topicId, group, carol, 'apr-carol'); // seq 2
    for (let i = 0; i < 3; i++) {
      const sent = await appMessage(group, `old ${i}`); // seq 3..5
      group = sent.group;
      await alice.call('POST', `/v1/topics/${topicId}/messages`, { message: sent.message });
    }
    // Bob keeps up; Carol never fetches.
    expect((await bob.call('GET', `/v1/topics/${topicId}/messages`)).body.messages.map((m: any) => m.seq)).toEqual([2, 3, 4, 5]);

    // Age the first four messages past the 30-day window.
    await relay.pool.query(
      "UPDATE mls_messages SET created_at = now() - interval '31 days' WHERE topic_id = $1 AND seq <= 4",
      [topicId],
    );
    const aliceEvents = await connectEvents(alice);
    const result = await runRetention(relay.ctx);
    expect(result.staleMembers).toEqual([{ topicId, deviceId: carol.deviceId }]);
    expect(await aliceEvents.next((e) => e.type === 'member_stale')).toEqual({
      type: 'member_stale',
      topic_id: topicId,
      device_id: carol.deviceId,
    });
    aliceEvents.close();

    const topic = (await alice.call('GET', `/v1/topics/${topicId}`)).body;
    expect(topic).toMatchObject({ min_seq: 5, last_seq: 5 });
    expect(topic.members.find((m: any) => m.handle === 'ret-carol').stale).toBe(true);
    expect((await memberCursor(topicId, alice)).stale_at).toBeNull(); // she wrote everything
    expect((await memberCursor(topicId, bob)).stale_at).toBeNull();

    // Fetching behind the window is Gone; a stale member is refused entirely.
    expect(await alice.call('GET', `/v1/topics/${topicId}/messages?after_seq=1`)).toMatchObject({
      status: 410,
      body: { error: 'pruned', details: { min_seq: 5 } },
    });
    expect((await alice.call('GET', `/v1/topics/${topicId}/messages?after_seq=4`)).body.messages.map((m: any) => m.seq)).toEqual([5]);
    expect((await carol.call('GET', `/v1/topics/${topicId}/messages`)).body.error).toBe('member_stale');
  });

  it('drops expired Welcomes and challenges', async () => {
    const alice = await Person.create(relay, 'exp-alice');
    const bob = await Person.create(relay, 'exp-bob');
    await bob.uploadKeyPackages(1);
    const { topicId, group } = await alice.createTopic();
    await addMember(alice, topicId, group, bob, 'apr');
    await relay.pool.query("UPDATE welcomes SET expires_at = now() - interval '1 minute' WHERE topic_id = $1", [topicId]);
    expect((await bob.call('GET', '/v1/inbox')).body.welcomes).toEqual([]);

    const result = await runRetention(relay.ctx);
    expect(result.welcomesDeleted).toBeGreaterThanOrEqual(1);
    expect((await relay.pool.query('SELECT 1 FROM welcomes WHERE topic_id = $1', [topicId])).rowCount).toBe(0);
  });
});
