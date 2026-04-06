export type ModelErrorCode =
  | 'MODEL_NOT_FOUND'
  | 'CHECKSUM_MISMATCH'
  | 'DOWNLOAD_FAILED'
  | 'DOWNLOAD_TIMEOUT'
  | 'DISK_FULL'
  | 'LOCK_TIMEOUT';

export class AgentArmorModelError extends Error {
  readonly code: ModelErrorCode;
  readonly cause?: Error;

  constructor(code: ModelErrorCode, message: string, cause?: Error) {
    super(message);
    this.name = 'AgentArmorModelError';
    this.code = code;
    this.cause = cause;
  }
}
