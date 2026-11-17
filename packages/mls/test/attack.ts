// Builds commits the honest TopicSession refuses, from a copy of a member's
// state. Used only by tests.

import {
  createCommit,
  encodeMlsMessage,
  getCiphersuiteFromName,
  getCiphersuiteImpl,
} from 'ts-mls';
import type { Proposal } from 'ts-mls';
import { defaultClientConfig } from 'ts-mls/clientConfig.js';
import { debugClientState } from '../src/ts-mls-engine.ts';
import type { GroupState, MlsEngine } from '../src/index.ts';

const impl = await getCiphersuiteImpl(getCiphersuiteFromName('MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519'));

export async function rawCommit(
  engine: MlsEngine,
  state: GroupState,
  proposals: Proposal[],
  authenticatedData: Uint8Array = new Uint8Array(),
  acceptAllCredentials = false,
): Promise<{ commit: Uint8Array; welcome?: Uint8Array }> {
  const original = debugClientState(engine.deserialize(engine.serialize(state)));
  const client = acceptAllCredentials
    ? {
        ...original,
        clientConfig: { ...defaultClientConfig, authService: { async validateCredential() { return true; } } },
      }
    : original;
  const result = await createCommit(
    // The attacker can have the PSK. Receivers in these tests do not, so a PSK
    // proposal fails closed when they process the commit.
    { state: client, cipherSuite: impl, pskIndex: { findPsk: () => new Uint8Array(32) } },
    { extraProposals: proposals, ratchetTreeExtension: true, authenticatedData },
  );
  return {
    commit: encodeMlsMessage(result.commit),
    ...(result.welcome
      ? { welcome: encodeMlsMessage({ welcome: result.welcome, wireformat: 'mls_welcome', version: 'mls10' }) }
      : {}),
  };
}
