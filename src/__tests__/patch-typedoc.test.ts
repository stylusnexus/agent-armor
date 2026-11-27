import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { ORIGINAL, PATCHED, patchSource } from '../../scripts/patch-typedoc.mjs';

describe('patch-typedoc', () => {
  it('replaces the call that minimatch 11 removed', () => {
    const out = patchSource(`before\n${ORIGINAL}\nafter`);
    expect(out).toBe(`before\n${PATCHED}\nafter`);
    expect(out).not.toContain('matchOne');
  });

  it('leaves patched source unchanged', () => {
    const patched = `before\n${PATCHED}\nafter`;
    expect(patchSource(patched)).toBe(patched);
  });

  it('fails on source it does not recognize', () => {
    expect(() => patchSource('some newer typedoc')).toThrow(/typedoc/);
  });

  // Fails when a typedoc upgrade makes the patch stale, so it gets removed.
  it('still applies to the installed typedoc', () => {
    const installed = readFileSync(resolve('node_modules/typedoc/dist/node-utils.js'), 'utf8');
    expect(patchSource(installed)).toContain(PATCHED);
  });
});
