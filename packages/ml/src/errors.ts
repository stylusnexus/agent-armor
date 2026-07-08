/** Error codes {@link AgentArmorModelError} can carry when model resolution fails. */
export type ModelErrorCode =
  | 'MODEL_NOT_FOUND'
  | 'CHECKSUM_MISMATCH'
  | 'DOWNLOAD_FAILED'
  | 'DOWNLOAD_TIMEOUT'
  | 'DISK_FULL'
  | 'LOCK_TIMEOUT';

/** Thrown when the ML model can't be resolved (missing, corrupt, or unreachable). */
export class AgentArmorModelError extends Error {
  /** Which failure mode this is — use this to branch on recoverable vs. fatal cases. */
  readonly code: ModelErrorCode;
  /** The underlying error, when this wraps one (e.g. a failed fetch). */
  readonly cause?: Error;

  constructor(code: ModelErrorCode, message: string, cause?: Error) {
    super(message);
    this.name = 'AgentArmorModelError';
    this.code = code;
    this.cause = cause;
  }
}
