import { describe, expect, it } from 'vitest';
import { ValidationError } from 'ts-mls/mlsError.js';
import { MlsOperationError, ReasonCode, toMlsOperationError } from '../src/index.ts';
import { DecodeError } from '@agent-bridge/protocol';

describe('engine errors become reason codes', () => {
  it('maps the library sentences in one place and does not repeat them', () => {
    const cases: Array<[unknown, string]> = [
      [new ValidationError('Desired generation too far in the future'), ReasonCode.generationGap],
      [new ValidationError('Desired gen in the past'), ReasonCode.generationPast],
      [new ValidationError('Cannot process message, epoch too old'), ReasonCode.epochTooOld],
      [new ValidationError('Cannot process commit or proposal from former epoch'), ReasonCode.epochTooOld],
      [new ValidationError('No matching secret found'), ReasonCode.keyPackageMismatch],
      [new ValidationError('Could not find pskId referenced in proposal'), ReasonCode.unsupportedProposal],
      [new ValidationError('Could not validate credential'), ReasonCode.invalidCredential],
      [
        new Error('This error should never occur, if you see this please submit a bug report. Message: Desired gen in the past'),
        ReasonCode.generationPast,
      ],
      [new ValidationError('Parent hash did not match the UpdatePath'), ReasonCode.mlsRejected],
      [Object.assign(new Error('AES failed'), { name: 'OperationError' }), ReasonCode.undecryptable],
      [Object.assign(new Error('tag'), { name: 'CryptoVerificationError' }), ReasonCode.undecryptable],
      [new DecodeError('unexpected end of input'), ReasonCode.truncated],
      [new DecodeError('unknown wire format'), ReasonCode.badFrame],
      [Object.assign(new Error('Could not decode PrivateMessageContent'), { name: 'CodecError' }), ReasonCode.badFrame],
      [new Error('something the library might say tomorrow'), ReasonCode.mlsError],
    ];
    for (const [err, code] of cases) {
      const mapped = toMlsOperationError(err);
      expect(mapped).toBeInstanceOf(MlsOperationError);
      expect(mapped.code).toBe(code);
      const library = err instanceof Error ? err.message : '';
      expect(mapped.message).not.toBe(library);
      expect(mapped.message.toLowerCase()).not.toContain('desired');
      expect(mapped.message).not.toContain('bug report');
    }
  });

  it('leaves an error that is already ours untouched', () => {
    const err = new MlsOperationError('topic_halted', 'topic is halted');
    expect(toMlsOperationError(err)).toBe(err);
  });
});
