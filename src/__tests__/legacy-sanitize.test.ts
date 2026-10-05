import { describe, expect, it } from 'vitest';
import { replaceRanges } from '../sanitize';
import { HiddenHTMLDetector, MetadataInjectionDetector, SyntacticMaskingDetector } from '../detectors/content-injection';
import { ExfiltrationDetector, JailbreakPatternDetector, SubAgentSpawningDetector } from '../detectors/behavioural-control';
import type { Detector, Threat } from '../types';

/**
 * The exported legacy detector classes sanitize in one pass (#170). The old way rebuilt the whole string once per
 * finding, which is quadratic in the number of findings. It is kept here as the reference: output must be
 * identical for edits that fit the text and do not overlap.
 */
type Range = { offset: number; length: number };

function rebuildPerEdit(content: string, ranges: Range[], replacementFor: (original: string) => string): string {
  let result = content;
  const sorted = [...ranges].sort((a, b) => b.offset - a.offset);
  for (const { offset, length } of sorted) {
    const original = result.slice(offset, offset + length);
    result = result.slice(0, offset) + replacementFor(original) + result.slice(offset + length);
  }
  return result;
}

function threatsFor(ranges: Range[]): Threat[] {
  return ranges.map((location) => ({ location, severity: 'high' }) as Threat);
}

function rng(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (s + 0x6d2b79f5) >>> 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Random text, and random ranges inside it that never overlap (they may touch, or be empty). */
function randomCase(rand: () => number): { content: string; ranges: Range[] } {
  const pieces = ['<!-- x -->', '<div hidden="true">', 'data-x="y"', 'ignore all', 'abc', ' ', '\n', '=\'q\'', 'é', '😀'];
  let content = '';
  for (let n = Math.floor(rand() * 40); n > 0; n--) content += pieces[Math.floor(rand() * pieces.length)];
  const cuts: number[] = [];
  for (let n = Math.floor(rand() * 12) * 2; n > 0; n--) cuts.push(Math.floor(rand() * (content.length + 1)));
  cuts.sort((a, b) => a - b);
  const ranges: Range[] = [];
  for (let i = 0; i + 1 < cuts.length; i += 2) ranges.push({ offset: cuts[i], length: cuts[i + 1] - cuts[i] });
  // Shuffle: the order the threats arrive in must not matter.
  for (let i = ranges.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    [ranges[i], ranges[j]] = [ranges[j], ranges[i]];
  }
  return { content, ranges };
}

/** What a class puts in place of a finding, read from the class itself on a one-character text. */
function replacementOf(detector: Detector): string {
  return detector.sanitize('x', threatsFor([{ offset: 0, length: 1 }]));
}

const classes: Array<[string, Detector, (original: string) => string]> = [
  ['HiddenHTMLDetector', new HiddenHTMLDetector(), () => ''],
  ['SyntacticMaskingDetector', new SyntacticMaskingDetector(), () => ''],
  ['JailbreakPatternDetector', new JailbreakPatternDetector(), () => replacementOf(new JailbreakPatternDetector())],
  ['ExfiltrationDetector', new ExfiltrationDetector(), () => replacementOf(new ExfiltrationDetector())],
  ['SubAgentSpawningDetector', new SubAgentSpawningDetector(), () => replacementOf(new SubAgentSpawningDetector())],
  [
    'MetadataInjectionDetector',
    new MetadataInjectionDetector(),
    (original) => (original.startsWith('<!--') ? '' : original.replace(/=\s*["'][^"']*["']/, '=""')),
  ],
];

describe.each(classes)('%s sanitize (#170)', (_name, detector, replacementFor) => {
  it('matches rebuilding the string per edit on random edits that fit the text', () => {
    const rand = rng(170);
    for (let n = 0; n < 3000; n++) {
      const { content, ranges } = randomCase(rand);
      expect(detector.sanitize(content, threatsFor(ranges))).toBe(rebuildPerEdit(content, ranges, replacementFor));
    }
  });

  it('leaves the text alone when there are no findings, and ignores findings with no location', () => {
    expect(detector.sanitize('keep me', [])).toBe('keep me');
    expect(detector.sanitize('keep me', [{ severity: 'high' } as Threat])).toBe('keep me');
  });

  it('sanitizes 100,000 findings in a 1 MB text in well under two seconds', () => {
    const unit = 'abc<!-- x -->def'; // one comment per 16 characters
    const content = unit.repeat(65_536); // 1,048,576 characters, 65,536 findings
    const ranges: Range[] = [];
    for (let at = 3; at + 10 <= content.length; at += 16) ranges.push({ offset: at, length: 10 });
    for (let at = 0; ranges.length < 100_000 && at + 2 <= content.length; at += 16) ranges.push({ offset: at, length: 0 });
    const threats = threatsFor(ranges);
    const start = performance.now();
    const out = detector.sanitize(content, threats);
    expect(performance.now() - start).toBeLessThan(2000);
    expect(out.length).toBeGreaterThan(0);
  });
});

describe('replaceRanges', () => {
  it('removes with an empty replacement and replaces with a string', () => {
    expect(replaceRanges('abcdef', [{ offset: 1, length: 2 }], '')).toBe('adef');
    expect(replaceRanges('abcdef', [{ offset: 1, length: 2 }, { offset: 4, length: 1 }], '#')).toBe('a#d#f');
  });

  it('passes the original text of each range to a replacement function', () => {
    expect(replaceRanges('xaybz', [{ offset: 1, length: 1 }, { offset: 3, length: 1 }], (s) => s.toUpperCase())).toBe('xAyBz');
  });

  it('appends instead of landing inside inserted text when an offset is past the end', () => {
    expect(replaceRanges('abc', [{ offset: 10, length: 2 }], '#')).toBe('abc#');
  });
});
