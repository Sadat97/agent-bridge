import {
  decodeBridgeCredential,
  decodeKeyPackageMessage,
  keyPackageRef,
} from '@agent-bridge/protocol';
import type { Credential } from './types.ts';

/** Public identity of an MLSMessage KeyPackage, as the relay stores it. */
export function readKeyPackage(message: Uint8Array): { ref: Uint8Array; signatureKey: Uint8Array; credential: Credential } {
  const summary = decodeKeyPackageMessage(message);
  return {
    ref: keyPackageRef(summary.keyPackage),
    signatureKey: summary.signatureKey,
    credential: decodeBridgeCredential(summary.credentialIdentity),
  };
}
