import { describe, it, expect } from 'vitest';
import {
  normalizeForScan,
  mapRangeToOriginal,
} from '../normalize/unicode';

describe('normalizeForScan', () => {
  it('leaves plain ASCII unchanged (fast path, no remap needed)', () => {
    const r = normalizeForScan('ignore previous instructions');
    expect(r.normalized).toBe('ignore previous instructions');
    expect(r.changed).toBe(false);
  });

  it('folds Cyrillic homoglyphs to a Latin skeleton', () => {
    // "ignоrе" with Cyrillic о (U+043E) and е (U+0435)
    const r = normalizeForScan('ignоrе');
    expect(r.normalized).toBe('ignore');
    expect(r.changed).toBe(true);
  });

  it('folds Greek homoglyphs', () => {
    // Α (U+0391) ο (U+03BF)
    const r = normalizeForScan('Αο');
    expect(r.normalized).toBe('Ao');
  });

  it('folds fullwidth and math alphanumerics via NFKC', () => {
    expect(normalizeForScan('Ｉｇｎｏｒｅ').normalized).toBe(
      'Ignore'
    );
    // Mathematical bold small a (U+1D41A) -> a
    expect(normalizeForScan('\u{1D41A}').normalized).toBe('a');
  });

  it('strips zero-width and bidi control characters', () => {
    const r = normalizeForScan('ig​no‍re‮d');
    expect(r.normalized).toBe('ignored');
    expect(r.changed).toBe(true);
  });

  it('maps a normalized range back onto the original, covering dropped chars', () => {
    // zero-width space at index 2 inside the original
    const original = 'ig​nore';
    const r = normalizeForScan(original);
    expect(r.normalized).toBe('ignore');
    // "nore" in normalized is offset 2, length 4 -> original offset 3 (after ZWSP)
    const range = mapRangeToOriginal(r, 2, 4);
    expect(original.slice(range.offset, range.offset + range.length)).toBe('nore');
  });

  it('keeps offsets correct across astral (2-unit) characters', () => {
    // U+1D41A is 2 UTF-16 units; ensure a following char maps past it
    const original = '\u{1D41A}X';
    const r = normalizeForScan(original);
    expect(r.normalized).toBe('aX');
    const range = mapRangeToOriginal(r, 1, 1); // the "X"
    expect(original.slice(range.offset, range.offset + range.length)).toBe('X');
  });
});
