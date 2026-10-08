import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';
import { HF_REVISION, MODEL_CHECKSUM, MODEL_VERSION } from '../src/constants';

describe('pinned model revision', () => {
  it('names a fixed revision, never the moving main branch', () => {
    expect(HF_REVISION).toBeTruthy();
    expect(HF_REVISION).not.toBe('main');
  });

  it('is a real SHA-256, not a placeholder', () => {
    expect(MODEL_CHECKSUM).toMatch(/^[0-9a-f]{64}$/);
  });

  it('bumps the cache folder together with the revision', () => {
    expect(MODEL_VERSION).toBe(HF_REVISION);
  });

  it('can be read by the model-integrity workflow (it greps constants.ts)', () => {
    const src = readFileSync(join(__dirname, '../src/constants.ts'), 'utf-8');
    const match = /^export const HF_REVISION = '(.*)';$/m.exec(src);
    expect(match?.[1]).toBe(HF_REVISION);
  });
});
