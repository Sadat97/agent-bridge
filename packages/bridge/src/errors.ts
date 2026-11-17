// Errors the agent surface returns. `message` is ours; it never includes a
// ts-mls sentence. `code` is the stable `error` field from DESIGN.md section 6.1.

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
