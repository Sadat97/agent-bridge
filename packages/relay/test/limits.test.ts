import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { ClientState, Proposal } from 'ts-mls';
import { appMessage, commit, connectEvents, decodeKeyPackage, nowSeconds, Person, startRelay } from './helpers.ts';
import type { TestRelay } from './helpers.ts';

async function addMember(owner: Person, topicId: string, group: ClientState, invitee: Person): Promise<ClientState> {
  const expiresAt = nowSeconds() + 3600;
  const approvalId = `apr-${invitee.handle}`;
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
  if (res.status !== 201) throw new Error(`add failed: ${JSON.stringify(res.body)}`);
  return committed.group;
}

function claim(owner: Person, topicId: string, invitee: Person, approvalId: string) {
  const expiresAt = nowSeconds() + 3600;
  return owner.call('POST', `/v1/devices/${invitee.deviceId}/key-packages/claim`, {
    topic_id: topicId,
    approval_id: approvalId,
    expires_at: expiresAt,
    approval: owner.signAdd(topicId, approvalId, invitee, expiresAt),
  });
}

function closed(socket: { once(event: 'close', cb: () => void): void }): Promise<void> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('socket stayed open')), 3000);
    socket.once('close', () => {
      clearTimeout(timer);
      resolve();
    });
  });
}

describe('KeyPackage claim identity', () => {
  let relay: TestRelay;
  beforeAll(async () => {
    relay = await startRelay();
  });
  afterAll(() => relay.close());

  it('scopes a reused approval id to the topic', async () => {
    const owner = await Person.create(relay, 'scope-owner');
    const invitee = await Person.create(relay, 'scope-invitee');
    await invitee.uploadKeyPackages(2);
    const topicA = await owner.createTopic();
    const topicB = await owner.createTopic();

    const first = await claim(owner, topicA.topicId, invitee, 'shared-id');
    const second = await claim(owner, topicB.topicId, invitee, 'shared-id');
    expect(first.status).toBe(200);
    expect(second.status).toBe(200);
    expect(second.body.key_package).not.toBe(first.body.key_package);
    expect((await invitee.call('GET', '/v1/key-packages/count')).body.unclaimed).toBe(0);

    const retry = await claim(owner, topicA.topicId, invitee, 'shared-id');
    expect(retry.body.key_package).toBe(first.body.key_package);
    expect((await invitee.call('GET', '/v1/key-packages/count')).body.unclaimed).toBe(0);
  });

  it('lets overlapping claims of one approval store a single KeyPackage', async () => {
    const owner = await Person.create(relay, 'race-owner');
    const invitee = await Person.create(relay, 'race-invitee');
    await invitee.uploadKeyPackages(4);
    const { topicId } = await owner.createTopic();

    const results = await Promise.all(Array.from({ length: 6 }, () => claim(owner, topicId, invitee, 'one-approval')));
    expect(results.every((result) => result.status === 200)).toBe(true);
    expect(new Set(results.map((result) => result.body.key_package)).size).toBe(1);
    expect((await invitee.call('GET', '/v1/key-packages/count')).body.unclaimed).toBe(3);
  });
});

describe('rate limits', () => {
  it('holds the KeyPackage claim cap under parallel requests', async () => {
    const relay = await startRelay({ keyPackageClaimsPerHour: 3 });
    try {
      const owner = await Person.create(relay, 'cap-owner');
      const invitee = await Person.create(relay, 'cap-invitee');
      await invitee.uploadKeyPackages(8);
      const { topicId } = await owner.createTopic();
      const results = await Promise.all(
        Array.from({ length: 8 }, (_, i) => claim(owner, topicId, invitee, `burst-${i}`)),
      );
      expect(results.filter((result) => result.status === 200)).toHaveLength(3);
      expect(results.filter((result) => result.status === 429)).toHaveLength(5);
      expect((await invitee.call('GET', '/v1/key-packages/count')).body.unclaimed).toBe(5);
    } finally {
      await relay.close();
    }
  });

  it('holds the post cap under parallel requests', async () => {
    const relay = await startRelay({ postsPerMinute: 3 });
    try {
      const owner = await Person.create(relay, 'post-owner');
      let { topicId, group } = await owner.createTopic();
      const messages: string[] = [];
      for (let i = 0; i < 6; i++) {
        const sent = await appMessage(group, `burst ${i}`);
        group = sent.group;
        messages.push(sent.message);
      }
      const results = await Promise.all(
        messages.map((message) => owner.call('POST', `/v1/topics/${topicId}/messages`, { message })),
      );
      expect(results.filter((result) => result.status === 201)).toHaveLength(3);
      expect(results.filter((result) => result.status === 429)).toHaveLength(3);
      expect(results.filter((result) => result.status === 201).map((result) => result.body.seq).sort((a, b) => a - b)).toEqual([
        1, 2, 3,
      ]);
    } finally {
      await relay.close();
    }
  });
});

describe('WebSocket revocation and expiry', () => {
  let relay: TestRelay;
  beforeAll(async () => {
    relay = await startRelay();
  });
  afterAll(() => relay.close());

  it('stops a revoked device from receiving, acking, or being answered', async () => {
    const alice = await Person.create(relay, 'rev-alice');
    const bob = await Person.create(relay, 'rev-bob');
    await bob.uploadKeyPackages(1);
    let { topicId, group } = await alice.createTopic();
    group = await addMember(alice, topicId, group, bob);
    const events = await connectEvents(bob);

    const cursor = async () => {
      const { rows } = await relay.pool.query<{ last_fetched_seq: number }>(
        'SELECT last_fetched_seq FROM topic_members WHERE topic_id = $1 AND device_id = $2',
        [topicId, bob.deviceId],
      );
      return rows[0]!.last_fetched_seq;
    };
    const before = await cursor();
    await relay.pool.query('UPDATE devices SET revoked_at = now() WHERE id = $1', [bob.deviceId]);

    const done = closed(events.socket);
    events.socket.send(JSON.stringify({ type: 'ack', topic_id: topicId, seq: 999 }));
    events.socket.send(JSON.stringify({ type: 'ping' }));
    const sent = await appMessage(group, 'after revoke');
    const post = await alice.call('POST', `/v1/topics/${topicId}/messages`, { message: sent.message });
    expect(post.status).toBe(201);
    await done;

    expect(events.events.filter((event) => event.type === 'pong')).toEqual([]);
    expect(events.events.filter((event) => event.type === 'message' && event.seq === post.body.seq)).toEqual([]);
    expect(await cursor()).toBe(before);
  });

  it('stops an expired socket from receiving, acking, or being answered', async () => {
    const alice = await Person.create(relay, 'ws-exp-alice');
    const bob = await Person.create(relay, 'ws-exp-bob');
    await bob.uploadKeyPackages(1);
    const { topicId, group } = await alice.createTopic();
    await addMember(alice, topicId, group, bob);

    const frames = await connectEvents(alice);
    const fanout = await connectEvents(alice);
    await relay.pool.query('UPDATE topic_members SET last_fetched_seq = 0 WHERE topic_id = $1 AND device_id = $2', [
      topicId,
      alice.deviceId,
    ]);

    relay.clock.offsetMs = 16 * 60 * 1000;
    try {
      const framesClosed = closed(frames.socket);
      frames.socket.send(JSON.stringify({ type: 'ack', topic_id: topicId, seq: 999 }));
      frames.socket.send(JSON.stringify({ type: 'ping' }));
      await framesClosed;
      expect(frames.events.filter((event) => event.type === 'pong')).toEqual([]);
      const cursor = await relay.pool.query<{ last_fetched_seq: number }>(
        'SELECT last_fetched_seq FROM topic_members WHERE topic_id = $1 AND device_id = $2',
        [topicId, alice.deviceId],
      );
      expect(cursor.rows[0]!.last_fetched_seq).toBe(0);

      await bob.login();
      const welcome = (await bob.call('GET', '/v1/inbox')).body.welcomes[0];
      const bobGroup = await bob.join(welcome.welcome);
      const note = await appMessage(bobGroup, 'after expiry');
      const fanoutClosed = closed(fanout.socket);
      const post = await bob.call('POST', `/v1/topics/${topicId}/messages`, { message: note.message });
      expect(post.status).toBe(201);
      await fanoutClosed;
      expect(fanout.events.filter((event) => event.type === 'message' && event.seq === post.body.seq)).toEqual([]);
    } finally {
      relay.clock.offsetMs = 0;
    }
  });
});
