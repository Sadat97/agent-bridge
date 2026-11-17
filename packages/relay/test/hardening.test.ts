import { describe, expect, it } from 'vitest';
import WebSocket from 'ws';
import type { Proposal } from 'ts-mls';
import { DEV_TOKEN_SECRET, loadConfig } from '../src/config.ts';
import { runRetention } from '../src/retention.ts';
import {
  appMessage,
  call,
  commit,
  connectEvents,
  decodeKeyPackage,
  nowSeconds,
  Person,
  startRelay,
} from './helpers.ts';
import type { TestRelay } from './helpers.ts';

const baseEnv = {
  DATABASE_URL: 'postgres://localhost/agent_bridge',
  RELAY_ORIGIN: 'http://127.0.0.1:8080',
  RELAY_TOKEN_SECRET: 'y'.repeat(32),
};

describe('config', () => {
  it('refuses the dev token secret in production and trusts a proxy only when configured', () => {
    expect(() =>
      loadConfig({ ...baseEnv, NODE_ENV: 'production', RELAY_TOKEN_SECRET: DEV_TOKEN_SECRET }),
    ).toThrow(/dev compose secret/);
    expect(loadConfig({ ...baseEnv, NODE_ENV: 'production' }).trustProxy).toBe(false);
    expect(loadConfig({ ...baseEnv, NODE_ENV: 'development', RELAY_TOKEN_SECRET: DEV_TOKEN_SECRET }).origin).toBe(
      'http://127.0.0.1:8080',
    );
    expect(loadConfig({ ...baseEnv, TRUST_PROXY: 'false' }).trustProxy).toBe(false);
    expect(loadConfig({ ...baseEnv, TRUST_PROXY: '10.0.0.8' }).trustProxy).toBe('10.0.0.8');
    expect(loadConfig({ ...baseEnv, TRUST_PROXY: 'true' }).trustProxy).toBe(true);
  });
});

describe('auth challenge caps', () => {
  it('caps outstanding challenges per device and drops expired ones immediately', async () => {
    const relay = await startRelay({ maxOutstandingChallengesPerDevice: 2 });
    try {
      const alice = await Person.create(relay, 'ch-alice');
      const challenge = () => call(relay, 'POST', '/v1/auth/challenge', { device_id: alice.deviceId });
      expect((await challenge()).status).toBe(200);
      expect((await challenge()).status).toBe(200);
      expect((await challenge()).status).toBe(429);
      await relay.pool.query("UPDATE auth_challenges SET expires_at = now() - interval '1 second' WHERE device_id = $1", [
        alice.deviceId,
      ]);
      expect((await challenge()).status).toBe(200);
      const left = await relay.pool.query('SELECT count(*)::int AS n FROM auth_challenges WHERE device_id = $1', [
        alice.deviceId,
      ]);
      expect(left.rows[0].n).toBe(1);
    } finally {
      await relay.close();
    }
  });

  it('caps outstanding challenges per client address', async () => {
    const relay = await startRelay({ maxOutstandingChallengesPerDevice: 10, maxOutstandingChallengesPerIp: 2 });
    try {
      const alice = await Person.create(relay, 'ip-alice');
      const bob = await Person.create(relay, 'ip-bob');
      expect((await call(relay, 'POST', '/v1/auth/challenge', { device_id: alice.deviceId })).status).toBe(200);
      expect((await call(relay, 'POST', '/v1/auth/challenge', { device_id: bob.deviceId })).status).toBe(200);
      expect((await call(relay, 'POST', '/v1/auth/challenge', { device_id: alice.deviceId })).status).toBe(429);
    } finally {
      await relay.close();
    }
  });
});

describe('upload and socket caps', () => {
  it('stops storing KeyPackages past the unclaimed cap', async () => {
    const relay = await startRelay({ maxUnclaimedKeyPackages: 2 });
    try {
      const alice = await Person.create(relay, 'kp-cap');
      const first = await alice.uploadKeyPackages(3);
      expect(first).toMatchObject({ status: 200, body: { accepted: 2, unclaimed: 2 } });
      const second = await alice.uploadKeyPackages(1);
      expect(second.status).toBe(429);
    } finally {
      await relay.close();
    }
  });

  it('refuses a WebSocket past the per-device cap', async () => {
    const relay = await startRelay({ maxSocketsPerDevice: 1 });
    try {
      const alice = await Person.create(relay, 'sock-alice');
      const first = await connectEvents(alice);
      const socket = new WebSocket(relay.baseUrl.replace('http', 'ws') + '/v1/ws', {
        headers: { authorization: `Bearer ${alice.token}` },
      });
      const code = await new Promise<number>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('socket was not closed')), 3000);
        socket.once('close', (closeCode) => {
          clearTimeout(timer);
          resolve(closeCode);
        });
        socket.once('error', (err) => {
          clearTimeout(timer);
          reject(err);
        });
      });
      expect(code).toBe(4029);
      expect(first.socket.readyState).toBe(WebSocket.OPEN);
      first.close();
    } finally {
      await relay.close();
    }
  });
});

async function addMember(owner: Person, topicId: string, group: Awaited<ReturnType<Person['createTopic']>>['group'], invitee: Person) {
  const expiresAt = nowSeconds() + 3600;
  const approvalId = `apr-${invitee.handle}`;
  const approval = owner.signAdd(topicId, approvalId, invitee, expiresAt);
  const claimed = await owner.call('POST', `/v1/devices/${invitee.deviceId}/key-packages/claim`, {
    topic_id: topicId,
    approval_id: approvalId,
    expires_at: expiresAt,
    approval,
  });
  if (claimed.status !== 200) throw new Error(`claim failed: ${JSON.stringify(claimed.body)}`);
  const add: Proposal = { proposalType: 'add', add: { keyPackage: decodeKeyPackage(claimed.body.key_package) } };
  const committed = await commit(group, [add]);
  const res = await owner.call('POST', `/v1/topics/${topicId}/messages`, {
    message: committed.message,
    membership: { adds: [{ device_id: invitee.deviceId, approval_id: approvalId, expires_at: expiresAt, approval }] },
    welcome: { message: committed.welcome, recipients: [invitee.deviceId] },
  });
  if (res.status !== 201) throw new Error(`add failed: ${JSON.stringify(res.body)}`);
  return committed.group;
}

describe('stale members', () => {
  async function ageAndRetain(relay: TestRelay, topicId: string) {
    await relay.pool.query("UPDATE mls_messages SET created_at = now() - interval '31 days' WHERE topic_id = $1", [topicId]);
    await runRetention(relay.ctx);
  }

  it('clears stale once the cursor catches the retained prefix', async () => {
    const relay = await startRelay();
    try {
      const alice = await Person.create(relay, 'stale-clear');
      let { topicId, group } = await alice.createTopic();
      const sent = await appMessage(group, 'kept');
      await alice.call('POST', `/v1/topics/${topicId}/messages`, { message: sent.message });
      await relay.pool.query('UPDATE topic_members SET last_fetched_seq = 0 WHERE topic_id = $1 AND device_id = $2', [
        topicId,
        alice.deviceId,
      ]);
      await ageAndRetain(relay, topicId);
      const stale = await relay.pool.query('SELECT stale_at FROM topic_members WHERE topic_id = $1 AND device_id = $2', [
        topicId,
        alice.deviceId,
      ]);
      expect(stale.rows[0].stale_at).not.toBeNull();

      const events = await connectEvents(alice);
      events.socket.send(JSON.stringify({ type: 'ack', topic_id: topicId, seq: 1 }));
      events.socket.send(JSON.stringify({ type: 'ping' }));
      await events.next((event) => event.type === 'pong');
      events.close();

      const cleared = await relay.pool.query<{ last_fetched_seq: number; stale_at: Date | null }>(
        'SELECT last_fetched_seq, stale_at FROM topic_members WHERE topic_id = $1 AND device_id = $2',
        [topicId, alice.deviceId],
      );
      expect(cleared.rows[0]).toMatchObject({ last_fetched_seq: 1, stale_at: null });
      expect((await alice.call('GET', `/v1/topics/${topicId}/messages?after_seq=1`)).status).toBe(200);
    } finally {
      await relay.close();
    }
  });

  it('lets a stale topic owner commit a re-add and still rejects their ordinary posts', async () => {
    const relay = await startRelay();
    try {
      const alice = await Person.create(relay, 'own-alice');
      const bob = await Person.create(relay, 'own-bob');
      const carol = await Person.create(relay, 'own-carol');
      await bob.uploadKeyPackages(1);
      await carol.uploadKeyPackages(1);
      const created = await alice.createTopic();
      const group = await addMember(alice, created.topicId, created.group, bob);
      const bobGroup = await bob.join((await bob.call('GET', '/v1/inbox')).body.welcomes[0].welcome);
      const bobMsg = await appMessage(bobGroup, 'bob spoke');
      expect((await bob.call('POST', `/v1/topics/${created.topicId}/messages`, { message: bobMsg.message })).status).toBe(201);
      await ageAndRetain(relay, created.topicId);

      const ordinary = await appMessage(group, 'owner chat');
      expect((await alice.call('POST', `/v1/topics/${created.topicId}/messages`, { message: ordinary.message })).body.error).toBe(
        'member_stale',
      );

      const expiresAt = nowSeconds() + 3600;
      const approval = alice.signAdd(created.topicId, 'apr-carol', carol, expiresAt);
      const claimed = await alice.call('POST', `/v1/devices/${carol.deviceId}/key-packages/claim`, {
        topic_id: created.topicId,
        approval_id: 'apr-carol',
        expires_at: expiresAt,
        approval,
      });
      expect(claimed.status).toBe(200);
      const add: Proposal = { proposalType: 'add', add: { keyPackage: decodeKeyPackage(claimed.body.key_package) } };
      const committed = await commit(group, [add]);
      const readd = await alice.call('POST', `/v1/topics/${created.topicId}/messages`, {
        message: committed.message,
        membership: { adds: [{ device_id: carol.deviceId, approval_id: 'apr-carol', expires_at: expiresAt, approval }] },
        welcome: { message: committed.welcome, recipients: [carol.deviceId] },
      });
      expect(readd.status).toBe(201);
      const carolRow = await relay.pool.query('SELECT stale_at FROM topic_members WHERE topic_id = $1 AND device_id = $2', [
        created.topicId,
        carol.deviceId,
      ]);
      expect(carolRow.rows[0].stale_at).toBeNull();
    } finally {
      await relay.close();
    }
  });
});

describe('leave_seq and close', () => {
  it('accepts any application message as leave_seq; section 5.8 must reject a non-leave', async () => {
    // The relay cannot read plaintext, so it cannot know the message is a leave.
    // DESIGN.md 5.1 checks only that leave_seq is an application message from that
    // device. DESIGN.md 5.8, on every bridge, is what rejects a citation that is
    // not a leave this bridge processed from that member.
    const relay = await startRelay();
    try {
      const alice = await Person.create(relay, 'leave-alice');
      const bob = await Person.create(relay, 'leave-bob');
      await bob.uploadKeyPackages(1);
      const created = await alice.createTopic();
      let group = await addMember(alice, created.topicId, created.group, bob);
      const bobGroup = await bob.join((await bob.call('GET', '/v1/inbox')).body.welcomes[0].welcome);
      const chat = await appMessage(bobGroup, 'hello, not a leave');
      const chatPost = await bob.call('POST', `/v1/topics/${created.topicId}/messages`, { message: chat.message });
      expect(chatPost.status).toBe(201);

      const remove = await commit(group, [{ proposalType: 'remove', remove: { removed: 1 } }]);
      const left = await alice.call('POST', `/v1/topics/${created.topicId}/messages`, {
        message: remove.message,
        membership: { removes: [{ device_id: bob.deviceId, approval_id: 'not-a-leave', leave_seq: chatPost.body.seq }] },
      });
      expect(left.status).toBe(201);
      const row = await relay.pool.query('SELECT change FROM membership_changes WHERE topic_id = $1 AND approval_id = $2', [
        created.topicId,
        'not-a-leave',
      ]);
      expect(row.rows[0].change).toBe('leave');
    } finally {
      await relay.close();
    }
  });

  it('rejects close from a member who is not the topic owner', async () => {
    const relay = await startRelay();
    try {
      const alice = await Person.create(relay, 'close-alice');
      const bob = await Person.create(relay, 'close-bob');
      await bob.uploadKeyPackages(1);
      const created = await alice.createTopic();
      await addMember(alice, created.topicId, created.group, bob);
      expect((await bob.call('POST', `/v1/topics/${created.topicId}/close`)).status).toBe(403);
      expect((await bob.call('POST', `/v1/topics/${created.topicId}/close`)).body.error).toBe('not_topic_owner');
      expect((await alice.call('POST', `/v1/topics/${created.topicId}/close`)).status).toBe(200);
    } finally {
      await relay.close();
    }
  });
});
