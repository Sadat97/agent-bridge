import { describe, expect, it } from 'vitest';
import {
  createApplicationMessage,
  createCommit,
  createGroup,
  defaultCapabilities,
  defaultLifetime,
  encodeMlsMessage,
  generateKeyPackage,
  getCiphersuiteFromName,
  getCiphersuiteImpl,
} from 'ts-mls';
import type { Proposal } from 'ts-mls';
import { encodeKeyPackage, makeKeyPackageRef } from 'ts-mls/keyPackage.js';
import {
  addApprovalContent,
  bytesToUuid,
  decodeBridgeCredential,
  decodeCommitApprovals,
  DecodeError,
  decodeKeyPackageMessage,
  decodeMlsMessageHeader,
  decodeWelcomeMessage,
  ed25519PublicKeyFromSeed,
  encodeBridgeCredential,
  encodeCommitApprovals,
  fromBase64,
  generateEd25519KeyPair,
  issueDeviceCert,
  keyPackageRef,
  removeApprovalContent,
  SignatureLabel,
  signWithLabel,
  TlsReader,
  TlsWriter,
  utf8,
  uuidToBytes,
  validateLeafCredential,
  verifyDeviceCert,
  verifyWithLabel,
} from '../src/index.ts';

describe('TLS encoding', () => {
  it('encodes MLS varints minimally (RFC 9420 section 2.1.2 examples)', () => {
    const cases: Array<[number, string]> = [
      [37, '25'],
      [15293, '7bbd'],
      [494878333, '9d7f3e7d'],
    ];
    for (const [value, hex] of cases) {
      const encoded = new TlsWriter().varint(value).finish();
      expect(Buffer.from(encoded).toString('hex')).toBe(hex);
      expect(new TlsReader(encoded).varint()).toBe(value);
    }
  });

  it('rejects non-minimal and reserved varints', () => {
    expect(() => new TlsReader(Uint8Array.of(0x40, 0x25)).varint()).toThrow(DecodeError);
    expect(() => new TlsReader(Uint8Array.of(0x80, 0x00, 0x00, 0x25)).varint()).toThrow(DecodeError);
    expect(() => new TlsReader(Uint8Array.of(0xc0, 0, 0, 0, 0, 0, 0, 1)).varint()).toThrow(DecodeError);
  });

  it('round-trips structs and detects truncation and trailing bytes', () => {
    const bytes = new TlsWriter().u8(7).u16(513).u64(2n ** 40n).opaque(utf8('hi')).finish();
    const r = new TlsReader(bytes);
    expect([r.u8(), r.u16(), r.u64(), Buffer.from(r.opaque()).toString()]).toEqual([7, 513, 2n ** 40n, 'hi']);
    r.end();
    expect(() => new TlsReader(bytes.subarray(0, 5)).u64()).toThrow(DecodeError);
    expect(() => new TlsReader(Uint8Array.of(1)).end()).toThrow(DecodeError);
  });
});

describe('bytes helpers', () => {
  it('accepts only strict base64', () => {
    expect(fromBase64('aGk=')).toEqual(utf8('hi'));
    expect(fromBase64('aGk')).toBeNull();
    expect(fromBase64('a$k=')).toBeNull();
  });

  it('maps UUIDs to 16 bytes and back', () => {
    const id = '0d9f6c5e-6f0b-4a0e-9a57-2a1d8f0b9c11';
    expect(bytesToUuid(uuidToBytes(id.toUpperCase()))).toBe(id);
  });
});

describe('signatures', () => {
  it('device certificates verify only under the issuing identity key', () => {
    const identity = generateEd25519KeyPair();
    const device = generateEd25519KeyPair();
    const fields = {
      handle: 'mohamed',
      deviceId: '0d9f6c5e-6f0b-4a0e-9a57-2a1d8f0b9c11',
      signatureKey: device.publicKey,
      createdAt: 1_763_300_000,
    };
    const cert = issueDeviceCert(identity.privateKey, fields);
    expect(verifyDeviceCert(cert, identity.publicKey)).toMatchObject(fields);
    expect(verifyDeviceCert(cert, generateEd25519KeyPair().publicKey)).toBeNull();

    const tampered = cert.slice();
    tampered[2] = tampered[2]! ^ 1; // flip a bit in the handle
    expect(verifyDeviceCert(tampered, identity.publicKey)).toBeNull();
    expect(verifyDeviceCert(cert.subarray(0, cert.length - 1), identity.publicKey)).toBeNull();
  });

  it('labels separate signature purposes', () => {
    const key = generateEd25519KeyPair();
    const content = removeApprovalContent({
      topicId: '0d9f6c5e-6f0b-4a0e-9a57-2a1d8f0b9c11',
      approvalId: 'apr_1',
      removedDeviceKey: generateEd25519KeyPair().publicKey,
    });
    const sig = signWithLabel(key.privateKey, SignatureLabel.remove, content);
    expect(verifyWithLabel(key.publicKey, SignatureLabel.remove, content, sig)).toBe(true);
    expect(verifyWithLabel(key.publicKey, SignatureLabel.add, content, sig)).toBe(false);
  });

  it('add approvals bind every field', () => {
    const owner = generateEd25519KeyPair();
    const base = {
      topicId: '0d9f6c5e-6f0b-4a0e-9a57-2a1d8f0b9c11',
      approvalId: 'apr_2',
      inviteeIdentityKey: generateEd25519KeyPair().publicKey,
      inviteeDeviceKey: generateEd25519KeyPair().publicKey,
      role: 'member' as const,
      expiresAt: 1_763_900_000,
    };
    const sig = signWithLabel(owner.privateKey, SignatureLabel.add, addApprovalContent(base));
    expect(verifyWithLabel(owner.publicKey, SignatureLabel.add, addApprovalContent(base), sig)).toBe(true);
    expect(
      verifyWithLabel(owner.publicKey, SignatureLabel.add, addApprovalContent({ ...base, expiresAt: 1_763_900_001 }), sig),
    ).toBe(false);
    expect(
      verifyWithLabel(owner.publicKey, SignatureLabel.add, addApprovalContent({ ...base, role: 'owner' }), sig),
    ).toBe(false);
  });

  it('derives the public key from a seed', () => {
    const pair = generateEd25519KeyPair();
    expect(ed25519PublicKeyFromSeed(pair.privateKey)).toEqual(pair.publicKey);
  });
});

describe('MLS framing against ts-mls', async () => {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName('MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519'));
  const topicId = '6b3e2a10-55c4-4c1e-8d0a-3f2b1c9e7a64';
  const credential = (name: string) => ({ credentialType: 'basic' as const, identity: utf8(name) });

  const alice = await generateKeyPackage(credential('alice'), defaultCapabilities(), defaultLifetime, [], impl);
  const bob = await generateKeyPackage(credential('bob'), defaultCapabilities(), defaultLifetime, [], impl);
  const group = await createGroup(uuidToBytes(topicId), alice.publicPackage, alice.privatePackage, [], impl);

  it('reads group_id, epoch and content type of an application message', async () => {
    const { privateMessage } = await createApplicationMessage(group, utf8('hello'), impl);
    const encoded = encodeMlsMessage({ privateMessage, wireformat: 'mls_private_message', version: 'mls10' });
    const header = decodeMlsMessageHeader(encoded);
    expect(header).toMatchObject({
      wireFormat: 'private_message',
      epoch: 0n,
      contentType: 'application',
      authenticatedData: new Uint8Array(),
    });
    if (header.wireFormat !== 'private_message') throw new Error('unreachable');
    expect(bytesToUuid(header.groupId)).toBe(topicId);
    expect(() => decodeMlsMessageHeader(encoded.subarray(0, encoded.length - 1))).toThrow(DecodeError);
  });

  it('reads a commit and recognises its Welcome', async () => {
    const add: Proposal = { proposalType: 'add', add: { keyPackage: bob.publicPackage } };
    const result = await createCommit(
      { state: group, cipherSuite: impl },
      { extraProposals: [add], ratchetTreeExtension: true, authenticatedData: utf8('approvals') },
    );
    const commit = encodeMlsMessage(result.commit);
    expect(decodeMlsMessageHeader(commit)).toMatchObject({
      wireFormat: 'private_message',
      epoch: 0n,
      contentType: 'commit',
      authenticatedData: utf8('approvals'),
    });

    const welcome = encodeMlsMessage({ welcome: result.welcome!, wireformat: 'mls_welcome', version: 'mls10' });
    expect(decodeMlsMessageHeader(welcome)).toEqual({ wireFormat: 'welcome' });
    expect(decodeWelcomeMessage(welcome)).toEqual({ cipherSuite: 1 });
    expect(() => decodeWelcomeMessage(commit)).toThrow(DecodeError);
  });

  it('reads KeyPackage fields and computes the same KeyPackageRef as ts-mls', async () => {
    const message = encodeMlsMessage({ keyPackage: bob.publicPackage, wireformat: 'mls_key_package', version: 'mls10' });
    const summary = decodeKeyPackageMessage(message);
    expect(summary.cipherSuite).toBe(1);
    expect(summary.signatureKey).toEqual(bob.publicPackage.leafNode.signaturePublicKey);
    expect(summary.credentialIdentity).toEqual(utf8('bob'));
    expect(summary.keyPackage).toEqual(encodeKeyPackage(bob.publicPackage));
    expect(keyPackageRef(summary.keyPackage)).toEqual(await makeKeyPackageRef(bob.publicPackage, impl.hash));
  });
});

describe('bridge credentials', () => {
  const deviceId = '0d9f6c5e-6f0b-4a0e-9a57-2a1d8f0b9c11';

  function credential() {
    const identity = generateEd25519KeyPair();
    const device = generateEd25519KeyPair();
    const deviceCert = issueDeviceCert(identity.privateKey, {
      handle: 'mohamed',
      deviceId,
      signatureKey: device.publicKey,
      createdAt: 1_763_300_000,
    });
    return {
      identity,
      device,
      encoded: encodeBridgeCredential({
        handle: 'mohamed',
        identityKey: identity.publicKey,
        deviceId,
        deviceCert,
      }),
    };
  }

  it('round-trips and validates only under the certified key and pin', () => {
    const cred = credential();
    const decoded = decodeBridgeCredential(cred.encoded);
    expect(decoded.handle).toBe('mohamed');
    expect(decoded.deviceId).toBe(deviceId);
    expect(validateLeafCredential(cred.encoded, cred.device.publicKey).ok).toBe(true);
    expect(validateLeafCredential(cred.encoded, cred.device.publicKey, cred.identity.publicKey).ok).toBe(true);
    expect(validateLeafCredential(cred.encoded, generateEd25519KeyPair().publicKey).ok).toBe(false);
    expect(validateLeafCredential(cred.encoded, cred.device.publicKey, generateEd25519KeyPair().publicKey).ok).toBe(false);
    expect(validateLeafCredential(utf8('alice'), cred.device.publicKey).ok).toBe(false);
    expect(() => encodeBridgeCredential({ ...decodeBridgeCredential(cred.encoded), handle: 'No' })).toThrow(TypeError);
  });
});

describe('CommitApprovals', () => {
  it('round-trips add, remove, and leave entries and rejects trailing bytes', () => {
    const deviceKey = generateEd25519KeyPair().publicKey;
    const encoded = encodeCommitApprovals({
      adds: [{ approvalId: 'apr_add', deviceKey, expiresAt: 1_763_900_000, signature: Uint8Array.of(1, 2, 3) }],
      removes: [
        { kind: 'remove', approvalId: 'apr_rm', deviceKey, signature: Uint8Array.of(4) },
        { kind: 'leave', approvalId: 'apr_lv', deviceKey, leaveSeq: 42 },
      ],
    });
    expect(decodeCommitApprovals(encoded)).toEqual({
      adds: [{ approvalId: 'apr_add', deviceKey, expiresAt: 1_763_900_000, signature: Uint8Array.of(1, 2, 3) }],
      removes: [
        { kind: 'remove', approvalId: 'apr_rm', deviceKey, signature: Uint8Array.of(4) },
        { kind: 'leave', approvalId: 'apr_lv', deviceKey, leaveSeq: 42 },
      ],
    });
    expect(decodeCommitApprovals(encodeCommitApprovals({ adds: [], removes: [] }))).toEqual({ adds: [], removes: [] });
    expect(() => decodeCommitApprovals(Uint8Array.of(...encoded, 0))).toThrow(DecodeError);
    expect(() => decodeCommitApprovals(Uint8Array.of(2, 0, 0))).toThrow(DecodeError);
    expect(() => decodeCommitApprovals(encoded.subarray(0, encoded.length - 1))).toThrow(DecodeError);
  });
});
