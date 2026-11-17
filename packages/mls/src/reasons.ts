// Stable reason codes for MLS failures.
//
// ts-mls reports failures as English sentences on typed errors (ValidationError,
// CodecError, CryptoError) and WebCrypto reports AEAD failure as OperationError.
// Those sentences are matched here and nowhere else. Callers store and show the
// code, and the message in REASON_TEXT, which does not include the library text.

import { MlsOperationError } from './errors.ts';

export const ReasonCode = {
  generationGap: 'generation_gap',
  generationPast: 'generation_past',
  epochTooOld: 'epoch_too_old',
  keyPackageMismatch: 'key_package_mismatch',
  unsupportedProposal: 'unsupported_proposal',
  invalidCredential: 'invalid_credential',
  undecryptable: 'undecryptable',
  truncated: 'truncated',
  badFrame: 'bad_frame',
  mlsRejected: 'mls_rejected',
  mlsError: 'mls_error',
  selfUpdateRequired: 'self_update_required',
} as const;

export type ReasonCode = (typeof ReasonCode)[keyof typeof ReasonCode];

/** Sentences a person or an agent may see. Keys are the codes above plus the session's own. */
export const REASON_TEXT: Record<string, string> = {
  [ReasonCode.generationGap]: 'The ratchet generation is further ahead than this bridge will skip.',
  [ReasonCode.generationPast]: 'The ratchet generation was already used.',
  [ReasonCode.epochTooOld]: 'The message belongs to an epoch this bridge no longer has.',
  [ReasonCode.keyPackageMismatch]: 'No stored KeyPackage matches this Welcome.',
  [ReasonCode.unsupportedProposal]: 'The commit contains a proposal this bridge does not accept.',
  [ReasonCode.invalidCredential]: 'The leaf credential is not valid.',
  [ReasonCode.undecryptable]: 'The message could not be decrypted.',
  [ReasonCode.truncated]: 'The message is truncated.',
  [ReasonCode.badFrame]: 'The message framing is not valid.',
  [ReasonCode.mlsRejected]: 'The MLS message was rejected.',
  [ReasonCode.mlsError]: 'The message could not be processed.',
  [ReasonCode.selfUpdateRequired]:
    'Discarding another draft would pass the unpublished generation cap. Commit a self-update before discarding more.',
};

/**
 * Exact ts-mls messages. Matching is equality, or a suffix, so an InternalError
 * that wraps one of these still maps. Adding a string here is the only place
 * that knows the library's wording.
 */
const LIBRARY_TEXT: Readonly<Record<string, ReasonCode>> = {
  'Desired generation too far in the future': ReasonCode.generationGap,
  'Desired gen in the past': ReasonCode.generationPast,
  'Cannot process message, epoch too old': ReasonCode.epochTooOld,
  'Cannot process commit or proposal from former epoch': ReasonCode.epochTooOld,
  'No matching secret found': ReasonCode.keyPackageMismatch,
  'Could not find pskId referenced in proposal': ReasonCode.unsupportedProposal,
  'Could not validate credential': ReasonCode.invalidCredential,
};

const LIBRARY_KEYS = Object.keys(LIBRARY_TEXT);

export function explainReason(code: string): string {
  return REASON_TEXT[code] ?? code;
}

/** Map anything thrown by the engine or by framing decode onto a stable error. */
export function toMlsOperationError(err: unknown): MlsOperationError {
  if (err instanceof MlsOperationError) return err;
  const name = errorName(err);
  const message = err instanceof Error ? err.message : '';
  const fromLibrary = libraryCode(message);
  if (fromLibrary) return new MlsOperationError(fromLibrary, REASON_TEXT[fromLibrary]!);
  if (name === 'OperationError' || name === 'CryptoError' || name === 'CryptoVerificationError') {
    return new MlsOperationError(ReasonCode.undecryptable, REASON_TEXT[ReasonCode.undecryptable]!);
  }
  if (message === 'unexpected end of input') {
    return new MlsOperationError(ReasonCode.truncated, REASON_TEXT[ReasonCode.truncated]!);
  }
  if (name === 'DecodeError' || name === 'CodecError') {
    return new MlsOperationError(ReasonCode.badFrame, REASON_TEXT[ReasonCode.badFrame]!);
  }
  if (name === 'ValidationError') {
    return new MlsOperationError(ReasonCode.mlsRejected, REASON_TEXT[ReasonCode.mlsRejected]!);
  }
  return new MlsOperationError(ReasonCode.mlsError, REASON_TEXT[ReasonCode.mlsError]!);
}

function libraryCode(message: string): ReasonCode | undefined {
  if (Object.hasOwn(LIBRARY_TEXT, message)) return LIBRARY_TEXT[message];
  for (const key of LIBRARY_KEYS) {
    if (message.endsWith(key)) return LIBRARY_TEXT[key];
  }
  return undefined;
}

function errorName(err: unknown): string {
  if (typeof err !== 'object' || err === null || !('name' in err)) return '';
  const name = err.name;
  return typeof name === 'string' ? name : '';
}
