import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { generateEd25519KeyPair, issueDeviceCert, relayAuthContent, SignatureLabel, signWithLabel, toBase64, fromBase64 } from '@agent-bridge/protocol';
import { call, Person, startRelay } from './helpers.ts';
import type { TestRelay } from './helpers.ts';

let relay: TestRelay;
beforeAll(async () => {
  relay = await startRelay();
});
afterAll(() => relay.close());

describe('registration', () => {
  it('registers a person and publishes their keys', async () => {
    const alice = await Person.create(relay, 'alice');
    const bob = await Person.create(relay, 'bob');

    const res = await bob.call('GET', '/v1/accounts/alice');
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({
      handle: 'alice',
      identity_pubkey: toBase64(alice.identity.publicKey),
      devices: [{ device_id: alice.deviceId, signature_pubkey: toBase64(alice.device.publicKey), revoked: false }],
    });
    expect(fromBase64(res.body.devices[0].cert)).toEqual(expect.any(Uint8Array));
  });

  it('rejects a device certificate that does not match', async () => {
    const mallory = new Person(relay, 'mallory');
    // Signed by the wrong identity key.
    const forged = issueDeviceCert(generateEd25519KeyPair().privateKey, {
      handle: 'mallory',
      deviceId: mallory.deviceId,
      signatureKey: mallory.device.publicKey,
      createdAt: 1,
    });
    expect((await mallory.register(forged)).body.error).toBe('invalid_device_cert');
    // Certifies a different handle.
    expect((await mallory.register(mallory.deviceCert({ handle: 'alice' }))).body.error).toBe('invalid_device_cert');
    expect((await mallory.register()).status).toBe(201);
  });

  it('rejects duplicate handles and devices', async () => {
    const first = await Person.create(relay, 'carol');
    const sameHandle = new Person(relay, 'carol');
    expect(await sameHandle.register()).toMatchObject({ status: 409, body: { error: 'handle_taken' } });

    const sameDevice = new Person(relay, 'carol2');
    Object.assign(sameDevice, { deviceId: first.deviceId });
    expect(await sameDevice.register()).toMatchObject({ status: 409, body: { error: 'device_exists' } });
  });

  it('validates handles', async () => {
    const res = await new Person(relay, 'Not A Handle').register();
    expect(res).toMatchObject({ status: 400, body: { error: 'invalid_request' } });
  });
});

describe('device login', () => {
  it('rejects a wrong signature and burns the challenge', async () => {
    const dave = await Person.create(relay, 'dave');
    const challenge = await call(relay, 'POST', '/v1/auth/challenge', { device_id: dave.deviceId });
    const nonce = fromBase64(challenge.body.nonce)!;

    const wrongKey = signWithLabel(generateEd25519KeyPair().privateKey, SignatureLabel.relayAuth, relayAuthContent(relay.ctx.config.origin, nonce));
    const bad = await call(relay, 'POST', '/v1/auth/token', { device_id: dave.deviceId, nonce: challenge.body.nonce, signature: toBase64(wrongKey) });
    expect(bad.status).toBe(401);

    const good = signWithLabel(dave.device.privateKey, SignatureLabel.relayAuth, relayAuthContent(relay.ctx.config.origin, nonce));
    const replay = await call(relay, 'POST', '/v1/auth/token', { device_id: dave.deviceId, nonce: challenge.body.nonce, signature: toBase64(good) });
    expect(replay).toMatchObject({ status: 401, body: { message: 'invalid or expired challenge' } });
  });

  it('binds the login signature to the relay origin', async () => {
    const erin = await Person.create(relay, 'erin');
    const challenge = await call(relay, 'POST', '/v1/auth/challenge', { device_id: erin.deviceId });
    const nonce = fromBase64(challenge.body.nonce)!;
    const otherRelay = signWithLabel(erin.device.privateKey, SignatureLabel.relayAuth, relayAuthContent('https://evil.example', nonce));
    const res = await call(relay, 'POST', '/v1/auth/token', { device_id: erin.deviceId, nonce: challenge.body.nonce, signature: toBase64(otherRelay) });
    expect(res.status).toBe(401);
  });

  it('rejects missing, forged, and expired access tokens', async () => {
    const frank = await Person.create(relay, 'frank');
    expect((await call(relay, 'GET', '/v1/topics')).status).toBe(401);
    expect((await call(relay, 'GET', '/v1/topics', undefined, frank.token.slice(0, -2) + 'xx')).status).toBe(401);
    expect((await frank.call('GET', '/v1/topics')).status).toBe(200);

    relay.clock.offsetMs = 16 * 60 * 1000;
    try {
      expect((await frank.call('GET', '/v1/topics')).status).toBe(401);
    } finally {
      relay.clock.offsetMs = 0;
    }
  });

  it('authenticates before validating the body', async () => {
    const res = await call(relay, 'POST', '/v1/topics', { id: 'not-a-uuid' });
    expect(res).toMatchObject({ status: 401, body: { error: 'unauthorized' } });
  });

  it('stops accepting tokens for a revoked device', async () => {
    const gina = await Person.create(relay, 'gina');
    await relay.pool.query('UPDATE devices SET revoked_at = now() WHERE id = $1', [gina.deviceId]);
    expect((await gina.call('GET', '/v1/topics')).status).toBe(401);
  });
});
