import { describe, expect, it } from 'vitest';
import { SELF_UPDATE_WAKE_CAP_MS, selfUpdateTimerDelay } from '../src/bridge.ts';

describe('self-update timer delay', () => {
  it('caps a delay that Node would clamp to 1 ms, and keeps a short one', () => {
    expect(selfUpdateTimerDelay(500, 0)).toBe(500);
    expect(selfUpdateTimerDelay(2_147_483_648, 0)).toBe(SELF_UPDATE_WAKE_CAP_MS);
    expect(selfUpdateTimerDelay(Number.MAX_SAFE_INTEGER, 0)).toBe(SELF_UPDATE_WAKE_CAP_MS);
    expect(SELF_UPDATE_WAKE_CAP_MS).toBeLessThanOrEqual(2_147_483_647);
    expect(selfUpdateTimerDelay(0, 1_000)).toBe(0);
  });
});
