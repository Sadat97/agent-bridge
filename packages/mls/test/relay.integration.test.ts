// Optional end-to-end check against the milestone-2 relay. Skipped when
// Postgres is not reachable; the relay tests use the same database.

import { randomUUID } from 'node:crypto';
import pg from 'pg';
import { describe, expect, it } from 'vitest';
import {
  decodeMlsMessageHeader,
  encodeCommitApprovals,
  fromBase64,
  relayAuthContent,
  SignatureLabel,
  signWithLabel,
  toBase64,
} from '@agent-bridge/protocol';
import { replenishKeyPackages, TopicSession } from '../src/index.ts';
import { later, makePerson, signAdd } from './helpers.ts';
import { call, ORIGIN, startRelay } from '../../relay/test/helpers.ts';
import type { TestRelay } from '../../relay/test/helpers.ts';

const ADMIN = process.env.TEST_DATABASE_URL ?? 'postgres://agent_bridge:agent_bridge@127.0.0.1:54329/agent_bridge';

async function postgresUp(): Promise<boolean> {
  const client = new pg.Client({ connectionString: ADMIN, connectionTimeoutMillis: 1000 });
  try {
    await client.connect();
    await client.end();
    return true;
  } catch {
    return false;
  }
}

const hasPostgres = await postgresUp();

describe.skipIf(!hasPostgres)('MlsEngine against the relay', () => {
  it('posts real MLS, and rejects a leave_seq the relay accepts because the message is not a leave', async () => {
    const relay = await startRelay();
    try {
      const alice = makePerson('alice');
      const bob = makePerson('bob');
      const carol = makePerson('carol');
      const aliceToken = await register(relay, alice);
      const bobToken = await register(relay, bob);
      const carolToken = await register(relay, carol);
      const topicId = randomUUID();

      const owner = await TopicSession.create({
        store: alice.store,
        engine: alice.engine,
        topicId,
        credential: alice.credential,
      });
      expect((await authed(relay, aliceToken, 'POST', '/v1/topics', { id: topicId })).status).toBe(201);

      const [bobPackage] = await replenishKeyPackages(bob.engine, bob.credential, bob.store, 1);
      const [carolPackage] = await replenishKeyPackages(carol.engine, carol.credential, carol.store, 1);
      expect((await authed(relay, bobToken, 'POST', '/v1/key-packages', { key_packages: [toBase64(bobPackage!)] })).status).toBe(200);
      expect((await authed(relay, carolToken, 'POST', '/v1/key-packages', { key_packages: [toBase64(carolPackage!)] })).status).toBe(200);

      const bobSession = await addMember(relay, aliceToken, alice, owner, bob, bobPackage!, 'apr-bob');
      const carolSession = await addMember(relay, aliceToken, alice, owner, carol, carolPackage!, 'apr-carol', [bobSession]);

      const update = await bobSession.stageMessage({ type: 'update', body: 'not a leave' });
      const posted = await authed(relay, bobToken, 'POST', `/v1/topics/${topicId}/messages`, {
        message: toBase64(update.message),
      });
      expect(posted.status).toBe(201);
      const updateSeq = posted.body.seq as number;
      await bobSession.confirmStaged(updateSeq);
      expect((await owner.receive(updateSeq, update.message)).kind).toBe('application');
      expect((await carolSession.receive(updateSeq, update.message)).kind).toBe('application');

      const bobLeaf = owner.members().find((member) => member.credential.handle === 'bob')!.leafIndex;
      const copy = owner.engine.deserialize(owner.engine.serialize(owner.confirmedState()));
      const bad = await owner.engine.commit(copy, {
        removes: [bobLeaf],
        authenticatedData: encodeCommitApprovals({
          adds: [],
          removes: [{ kind: 'leave', approvalId: 'apr-not-leave', deviceKey: bob.device.publicKey, leaveSeq: updateSeq }],
        }),
      });
      expect(decodeMlsMessageHeader(bad.commit)).toMatchObject({ contentType: 'commit' });
      const accepted = await authed(relay, aliceToken, 'POST', `/v1/topics/${topicId}/messages`, {
        message: toBase64(bad.commit),
        membership: { removes: [{ device_id: bob.deviceId, approval_id: 'apr-not-leave', leave_seq: updateSeq }] },
      });
      // The relay only checks that leave_seq is some application message from Bob.
      expect(accepted.status).toBe(201);
      const commitSeq = accepted.body.seq as number;
      expect(await carolSession.receive(commitSeq, bad.commit)).toMatchObject({
        kind: 'halted',
        reason: 'leave_seq is not a leave message',
      });
      expect(carolSession.epoch).toBe(owner.epoch);
      await expect(carolSession.stageMessage({ type: 'update', body: 'after' })).rejects.toMatchObject({ code: 'topic_halted' });
    } finally {
      await relay.close();
    }
  });
});

async function register(relay: TestRelay, person: ReturnType<typeof makePerson>): Promise<string> {
  const created = await call(relay, 'POST', '/v1/accounts', {
    handle: person.handle,
    identity_pubkey: toBase64(person.identity.publicKey),
    device: {
      id: person.deviceId,
      signature_pubkey: toBase64(person.device.publicKey),
      cert: toBase64(person.credential.deviceCert),
    },
  });
  if (created.status !== 201) throw new Error(`register ${person.handle}: ${JSON.stringify(created.body)}`);
  const challenge = await call(relay, 'POST', '/v1/auth/challenge', { device_id: person.deviceId });
  const nonce = fromBase64(challenge.body.nonce);
  if (!nonce) throw new Error('challenge nonce');
  const signature = signWithLabel(person.device.privateKey, SignatureLabel.relayAuth, relayAuthContent(ORIGIN, nonce));
  const token = await call(relay, 'POST', '/v1/auth/token', {
    device_id: person.deviceId,
    nonce: challenge.body.nonce,
    signature: toBase64(signature),
  });
  if (token.status !== 200) throw new Error(`login ${person.handle}: ${JSON.stringify(token.body)}`);
  return token.body.access_token as string;
}

async function authed(relay: TestRelay, token: string, method: string, path: string, body?: unknown) {
  return call(relay, method, path, body, token);
}

async function addMember(
  relay: TestRelay,
  ownerToken: string,
  alice: ReturnType<typeof makePerson>,
  owner: TopicSession,
  invitee: ReturnType<typeof makePerson>,
  keyPackage: Uint8Array,
  approvalId: string,
  already: TopicSession[] = [],
): Promise<TopicSession> {
  const expiresAt = later();
  const signature = signAdd(alice, owner.topicId, approvalId, invitee, expiresAt);
  const claim = await authed(relay, ownerToken, 'POST', `/v1/devices/${invitee.deviceId}/key-packages/claim`, {
    topic_id: owner.topicId,
    approval_id: approvalId,
    expires_at: expiresAt,
    approval: toBase64(signature),
  });
  if (claim.status !== 200) throw new Error(`claim: ${JSON.stringify(claim.body)}`);
  const staged = await owner.stageCommit({
    adds: [{ keyPackage: fromBase64(claim.body.key_package) ?? keyPackage, approvalId, expiresAt, signature }],
  });
  const posted = await authed(relay, ownerToken, 'POST', `/v1/topics/${owner.topicId}/messages`, {
    message: toBase64(staged.message),
    membership: {
      adds: [{ device_id: invitee.deviceId, approval_id: approvalId, expires_at: expiresAt, approval: toBase64(signature) }],
    },
    welcome: { message: toBase64(staged.welcome!), recipients: [invitee.deviceId] },
  });
  if (posted.status !== 201) throw new Error(`add post: ${JSON.stringify(posted.body)}`);
  await owner.confirmStaged(posted.body.seq);
  for (const member of already) await member.receive(posted.body.seq, staged.message);
  const joined = await TopicSession.join({
    store: invitee.store,
    engine: invitee.engine,
    topicId: owner.topicId,
    welcome: staged.welcome!,
    credential: invitee.credential,
    ownerIdentityKey: alice.identity.publicKey,
    commitSeq: posted.body.seq,
  });
  await joined.acceptJoin();
  return joined;
}
