// Errors the agent surface returns. `message` is ours; it never includes a
// ts-mls sentence. `code` is the stable `error` field from DESIGN.md section 6.1.

import { MlsOperationError, explainReason } from '@agent-bridge/mls';

const SURFACE_STATUS: Record<string, number> = {
  not_found: 404,
  unauthorized: 401,
  out_of_scope: 403,
  invalid_patch: 400,
  invalid_request: 400,
  invalid_passphrase: 401,
  topic_halted: 409,
  topic_pending_join: 409,
  topic_left: 409,
  topic_closed: 409,
  topic_stale: 409,
  self_update_required: 409,
  contact_key_changed: 409,
  generation_gap: 409,
  generation_past: 409,
  relay_unavailable: 503,
  mls_error: 500,
  seq_gap: 409,
};

export class BridgeError extends Error {
  readonly code: string;
  readonly status: number;
  readonly details: Record<string, unknown>;

  constructor(code: string, message: string, status = 400, details: Record<string, unknown> = {}) {
    super(message);
    this.name = 'BridgeError';
    this.code = code;
    this.status = status;
    this.details = details;
  }

  body(): { error: string; message: string; details: Record<string, unknown> } {
    return { error: this.code, message: this.message, details: this.details };
  }
}

export function invalid(message: string): BridgeError {
  return new BridgeError('invalid_request', message);
}

/** Map an engine error onto the agent-facing code. Library sentences stay inside the MLS package. */
export function toSurfaceError(err: unknown): BridgeError {
  if (err instanceof BridgeError) return err;
  if (err instanceof MlsOperationError) {
    const known = explainReason(err.code);
    const message = known === err.code ? err.message : known;
    return new BridgeError(err.code, message, SURFACE_STATUS[err.code] ?? 400);
  }
  return new BridgeError('mls_error', 'the message could not be processed', 500);
}
