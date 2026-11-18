export { BridgeError } from './errors.ts';
export { Bridge, bridgePaths, initBridge, openBridge } from './bridge.ts';
export type { AgentCaller, BridgeConfig } from './bridge.ts';
export { fingerprint, fingerprintDigits, fingerprintQrPayload, parseFingerprint } from './fingerprint.ts';
export { SELF_UPDATE_INTERVAL_MS } from './bridge.ts';
export type { ContactView } from './bridge.ts';
export { DEFAULT_POLICY, loadPolicy } from './policy.ts';
export { applyPatch, canonicalize, hashBytes, hashLabel } from './json.ts';
