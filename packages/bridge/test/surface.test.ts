import { describe, expect, it } from 'vitest';
import { MlsOperationError, ReasonCode } from '@agent-bridge/mls';
import { BridgeError, toSurfaceError } from '../src/errors.ts';

describe('agent-facing errors', () => {
  it('maps self_update_required to a 409 BridgeError and does not keep the library sentence', () => {
    const err = toSurfaceError(new MlsOperationError(ReasonCode.selfUpdateRequired, 'Desired generation too far in the future'));
    expect(err).toBeInstanceOf(BridgeError);
    expect(err.code).toBe('self_update_required');
    expect(err.status).toBe(409);
    expect(err.message.toLowerCase()).not.toContain('desired');
    expect(err.body().error).toBe('self_update_required');
  });
});
