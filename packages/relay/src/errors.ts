// Every error response has the shape { error, message, details? }.

export class RelayError extends Error {
  readonly statusCode: number;
  readonly code: string;
  readonly details: Record<string, unknown> | undefined;

  constructor(statusCode: number, code: string, message: string, details?: Record<string, unknown>) {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
    this.details = details;
  }
}

export const badRequest = (code: string, message: string, details?: Record<string, unknown>) =>
  new RelayError(400, code, message, details);
export const unauthorized = (message = 'authentication required') => new RelayError(401, 'unauthorized', message);
export const forbidden = (code: string, message: string) => new RelayError(403, code, message);
/** Also used for topics the caller is not a member of, so existence is not revealed. */
export const notFound = (message = 'not found') => new RelayError(404, 'not_found', message);
export const conflict = (code: string, message: string, details?: Record<string, unknown>) =>
  new RelayError(409, code, message, details);
export const gone = (code: string, message: string, details?: Record<string, unknown>) =>
  new RelayError(410, code, message, details);
export const tooManyRequests = (message: string) => new RelayError(429, 'rate_limited', message);
