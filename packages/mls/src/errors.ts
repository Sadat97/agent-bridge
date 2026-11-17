export class MlsOperationError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = 'MlsOperationError';
    this.code = code;
  }
}
