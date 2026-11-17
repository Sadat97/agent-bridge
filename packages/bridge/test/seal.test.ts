import { mkdtempSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { generateEd25519KeyPair, utf8 } from '@agent-bridge/protocol';
import { MlsStore, TopicSession, createTsMlsEngine, replenishKeyPackages } from '@agent-bridge/mls';
import { issueDeviceCert } from '@agent-bridge/protocol';
import { randomUUID } from 'node:crypto';
import { AesGcmSealer, randomStorageKey, unwrapPassphrase, wrapPassphrase } from '../src/seal.ts';
import { LocalStore } from '../src/local.ts';

describe('secrets at rest', () => {
  it('round-trips a storage key and rejects a wrong passphrase', () => {
    const key = randomStorageKey();
    const sealer = new AesGcmSealer(key);
    const plain = utf8('device-seed-device-seed-device-se');
    const aad = utf8('device-key:abc');
    const sealed = sealer.seal(plain, aad);
    expect(sealer.open(sealed, aad)).toEqual(plain);
    expect(() => sealer.open(sealed, utf8('other'))).toThrow(/could not be opened/);
    const wrapped = wrapPassphrase(plain, 'correct horse', utf8('identity-key:ada'));
    expect(unwrapPassphrase(wrapped, 'correct horse', utf8('identity-key:ada'))).toEqual(plain);
    expect(() => unwrapPassphrase(wrapped, 'nope', utf8('identity-key:ada'))).toThrow(/passphrase/);
  });

  it('does not write the identity key, device key, or MLS state as plaintext', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'agb-seal-'));
    const path = join(dir, 'store.sqlite');
    const identity = generateEd25519KeyPair();
    const device = generateEd25519KeyPair();
    const deviceId = randomUUID();
    const cert = issueDeviceCert(identity.privateKey, {
      handle: 'ada',
      deviceId,
      signatureKey: device.publicKey,
      createdAt: 1_700_000_000,
    });
    const sealer = new AesGcmSealer(randomStorageKey());
    const mls = new MlsStore(path, { sealer });
    const local = new LocalStore(path);
    local.saveIdentity('ada', identity.publicKey, wrapPassphrase(identity.privateKey, 'secret', utf8('identity-key:ada')));
    local.saveDevice(deviceId, device.publicKey, sealer.seal(device.privateKey, utf8(`device-key:${deviceId}`)), cert);
    const credential = { handle: 'ada', identityKey: identity.publicKey, deviceId, deviceCert: cert };
    const engine = createTsMlsEngine({ devicePrivateKey: device.privateKey, pins: mls.pins });
    await replenishKeyPackages(engine, credential, mls, 1);
    const topicId = randomUUID();
    const session = await TopicSession.create({ store: mls, engine, topicId, credential });
    const rawState = engine.serialize(session.confirmedState());
    local.db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
    local.close();
    mls.close();
    const files = ['', '-wal', '-shm'].flatMap((suffix) => {
      try {
        return [readFileSync(path + suffix)];
      } catch {
        return [];
      }
    });
    const disk = Buffer.concat(files);
    expect(statSync(path).size).toBeGreaterThan(0);
    expect(disk.includes(Buffer.from(identity.privateKey))).toBe(false);
    expect(disk.includes(Buffer.from(device.privateKey))).toBe(false);
    expect(disk.includes(Buffer.from(rawState))).toBe(false);
    expect(disk.includes(Buffer.from('secret'))).toBe(false);
  });
});
