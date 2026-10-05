import { describe, it, expect } from 'vitest';
import { MATCHERS } from '../patterns/matchers';
import { DEFAULT_PATTERNS } from '../patterns/default-patterns';
import { ALL_SAMPLES } from '../../scripts/eval/samples';

/**
 * #175: every hand-written matcher must find exactly what its regex finds.
 * Inputs are small (<= ~200 chars) so even the slow regexes finish; the
 * speed side is covered by pattern-time-budget.test.ts.
 *
 * CASES (env FUZZ_CASES) sets the number of inputs per matcher; SEED
 * (env FUZZ_SEED) picks the random sequence. Failures print both.
 */
const CASES = Number(process.env.FUZZ_CASES ?? 20_000);
const SEED = Number(process.env.FUZZ_SEED ?? 175);

function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const COMMON_ATOMS = [
  ' ', '  ', '\t', '\n', '\r', ' ', ' ', '"', "'", '`', '<', '>', '/', '</', '=', ':', ';',
  '(', ')', '[', ']', '{', '}', '#', '!', '.', ',', '-', '_', '0', '1', 'a', 'x', 'A', 'é',
];

const EDGE_LENGTHS = [0, 1, 2, 9, 10, 11, 19, 20, 21, 39, 40, 41, 49, 50, 51, 59, 60, 61, 79, 80, 81, 100, 499, 500, 501, 502, 1000, 1001];
const FILLERS = ['a', 'x', ' ', '\n', 'A', '-', '_', '0', '/', '='];

const SAMPLE_WINDOWS = ALL_SAMPLES.flatMap((s) => {
  const out: string[] = [];
  for (let i = 0; i < s.content.length; i += 120) out.push(s.content.slice(i, i + 200));
  return out;
});

function reference(regex: string, flags: string, group: number, content: string) {
  const re = new RegExp(regex, flags);
  const hits: Array<{ index: number; text: string; extracted: string | undefined }> = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(content)) !== null) {
    hits.push({ index: m.index, text: m[0], extracted: m[group] });
    if (m[0].length === 0) re.lastIndex++;
  }
  return hits;
}

describe('matchers are equivalent to the regexes they replace (#175)', () => {
  it('has a matcher bound to a shipped pattern for every entry', () => {
    const shipped = new Set(
      Object.values(DEFAULT_PATTERNS.detectors)
        .flat()
        .map((e) => `${e.flags}\u0000${e.extractGroup ?? 0}\u0000${e.regex}`),
    );
    for (const m of MATCHERS) {
      expect(shipped.has(`${m.flags}\u0000${m.extractGroup}\u0000${m.regex}`), `no shipped pattern has this regex: ${m.regex}`).toBe(true);
    }
  });

  for (const m of MATCHERS) {
    const entry = Object.values(DEFAULT_PATTERNS.detectors)
      .flat()
      .find((e) => e.regex === m.regex && e.flags === m.flags && (e.extractGroup ?? 0) === m.extractGroup);
    const label = entry?.id ?? m.regex.slice(0, 40);
    const group = m.extractGroup;

    it(`${label}: same matches on ${CASES} generated inputs`, () => {
      const rand = rng(SEED ^ [...label].reduce((h, c) => (h * 31 + c.charCodeAt(0)) | 0, 7));
      const atoms = [...m.fuzzAtoms, ...COMMON_ATOMS];
      for (let i = 0; i < CASES; i++) {
        let input = '';
        const mode = rand();
        if (mode < 0.25) {
          // an eval sample window with random fragments spliced in
          input = SAMPLE_WINDOWS[Math.floor(rand() * SAMPLE_WINDOWS.length)];
          for (let k = Math.floor(rand() * 4); k > 0; k--) {
            const at = Math.floor(rand() * (input.length + 1));
            input = input.slice(0, at) + atoms[Math.floor(rand() * atoms.length)] + input.slice(at);
          }
          if (rand() < 0.5) input = input.slice(0, Math.floor(rand() * (input.length + 1)));
        } else if (mode < 0.5) {
          // atoms with long filler runs, to reach the {m,n} edges (10, 20, 40, 50, 60, 80, 500 ...)
          const parts = 1 + Math.floor(rand() * 8);
          for (let k = 0; k < parts; k++) {
            input += m.fuzzAtoms[Math.floor(rand() * m.fuzzAtoms.length)];
            if (rand() < 0.6) {
              const len = EDGE_LENGTHS[Math.floor(rand() * EDGE_LENGTHS.length)] + Math.floor(rand() * 3) - 1;
              input += FILLERS[Math.floor(rand() * FILLERS.length)].repeat(Math.max(0, len));
            }
          }
        } else {
          const parts = 1 + Math.floor(rand() * 30);
          for (let k = 0; k < parts; k++) {
            const pool = rand() < 0.7 ? m.fuzzAtoms : atoms;
            input += pool[Math.floor(rand() * pool.length)];
          }
        }
        const expected = reference(m.regex, m.flags, group, input);
        const actual = m.match(input).map((h) => ({ index: h.index, text: h.text, extracted: group ? h.extracted : undefined }));
        const expectedNorm = expected.map((h) => ({ ...h, extracted: group ? h.extracted : undefined }));
        if (JSON.stringify(actual) !== JSON.stringify(expectedNorm)) {
          expect.fail(
            `seed ${SEED} case ${i}\ninput: ${JSON.stringify(input)}\nexpected: ${JSON.stringify(expectedNorm)}\nactual:   ${JSON.stringify(actual)}`,
          );
        }
      }
    }, 900_000);
  }
});
