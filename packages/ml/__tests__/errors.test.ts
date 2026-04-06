import { describe, it, expect } from 'vitest';
import { AgentArmorModelError } from '../src/errors';

describe('AgentArmorModelError', () => {
  it('creates error with code and message', () => {
    const err = new AgentArmorModelError('MODEL_NOT_FOUND', 'Model not found');
    expect(err.code).toBe('MODEL_NOT_FOUND');
    expect(err.message).toBe('Model not found');
    expect(err.name).toBe('AgentArmorModelError');
    expect(err).toBeInstanceOf(Error);
  });

  it('includes cause when provided', () => {
    const cause = new Error('network error');
    const err = new AgentArmorModelError('DOWNLOAD_FAILED', 'Download failed', cause);
    expect(err.cause).toBe(cause);
  });

  it('supports all error codes', () => {
    const codes = ['MODEL_NOT_FOUND', 'CHECKSUM_MISMATCH', 'DOWNLOAD_FAILED', 'DOWNLOAD_TIMEOUT', 'DISK_FULL', 'LOCK_TIMEOUT'] as const;
    for (const code of codes) {
      const err = new AgentArmorModelError(code, `Test ${code}`);
      expect(err.code).toBe(code);
    }
  });
});
