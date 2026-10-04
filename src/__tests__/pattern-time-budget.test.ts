import { describe, it, expect } from 'vitest';
import { DEFAULT_PATTERNS } from '../patterns/default-patterns';
import type { PatternEntry } from '../patterns/pattern-db';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { ADVERSARIAL_SAMPLES } from '../../scripts/eval/samples';

/**
 * #175: every shipped pattern must stay fast on adversarial input. A regex
 * that backtracks badly lets a few kilobytes freeze a synchronous scan.
 *
 * Each pattern is run against repeated fragments: single characters that
 * stress whitespace/bracket/bidi runs, trigger fragments that open a match
 * which never closes, and the first 60% of every adversarial eval sample (a
 * real trigger with its closing half cut off). Input grows in three steps so a
 * pattern that is cubic fails at the small size instead of hanging the test.
 */

const STEPS: Array<{ chars: number; budgetMs: number }> = [
  { chars: 4_000, budgetMs: 150 },
  { chars: 40_000, budgetMs: 400 },
  { chars: 200_000, budgetMs: 400 },
];

const FRAGMENTS = [
  '\n', ' ', '\t', '<', '>', '‪', '‬', '​', '-', '.', 'a', '0', '"', "'", '(', ')',
  '[', ']', '!', '=', '/', ':', '#', '*', '\\', '<a ', '![', '<!--', '\n\n ', '  \n',
  '<a style="display:none">', '<p style="opacity:0" >', 'data-x="', '![a](http://x/?data=',
  'if(isBot){', '[//]: # (ignore ', 'SYSTEM: ', 'DAN ', 'assistant, ', 'note to the ai ',
  '‪ x ', 'aria-label="', 'alt="',
  '![a][b] ', 'eval $(echo ', 'echo -n ', 'important message from me ',
];

const SAMPLE_PREFIXES = ADVERSARIAL_SAMPLES.map((s) =>
  s.content.slice(0, Math.ceil(s.content.length * 0.6)),
).filter((s) => s.length > 0);

const UNITS = [...new Set([...FRAGMENTS, ...SAMPLE_PREFIXES])];

/**
 * Runs one pattern against every unit and step, in a separate Node process
 * (fixtures/time-pattern.ts; it uses the pattern's matcher when it has one,
 * like the detector does). A regex that backtracks catastrophically cannot be
 * interrupted from inside the thread running it (not even by
 * worker.terminate()), but the parent can kill the process, so a regression
 * fails this test instead of hanging it.
 */
const TIME_PATTERN = fileURLToPath(new URL('./fixtures/time-pattern.ts', import.meta.url));
/**
 * Fragments taken from the pattern's own source: each literal word on its own
 * and with a separator, and the first two words as a phrase. Triggers that a
 * pattern's author wrote into it are the likeliest start of a runaway match.
 */
function ownUnits(entry: PatternEntry): string[] {
  const words = [...new Set(entry.regex.match(/[A-Za-z][A-Za-z_-]{2,}/g) ?? [])];
  const units = words.flatMap((w) => [w, `${w}-`, `${w}=`, `${w} `, `${w}\n`]);
  if (words.length >= 2) units.push(`${words[0]} ${words[1]}\n`, `${words[0]}${words[1]}=`);
  return units;
}

const DEADLINE_MS = 60_000;

function checkPattern(entry: PatternEntry): Promise<string[]> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--import', 'tsx', TIME_PATTERN], { stdio: ['pipe', 'pipe', 'inherit'] });
    let out = '';
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      resolve([`${entry.id}: did not finish within ${DEADLINE_MS}ms (catastrophic backtracking)`]);
    }, DEADLINE_MS);
    child.stdout.on('data', (d) => (out += d));
    child.once('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
    child.once('close', () => {
      clearTimeout(timer);
      try {
        resolve(JSON.parse(out) as string[]);
      } catch {
        /* killed on deadline; already resolved */
      }
    });
    child.stdin.end(
      JSON.stringify({
        entry: { id: entry.id, regex: entry.regex, flags: entry.flags, extractGroup: entry.extractGroup },
        units: [...new Set([...UNITS, ...ownUnits(entry)])],
        steps: STEPS,
      }),
    );
  });
}

describe('shipped patterns stay fast on adversarial input (#175)', () => {
  it('no pattern exceeds its time budget on any repeated fragment', { timeout: 900_000 }, async () => {
    const entries = Object.values(DEFAULT_PATTERNS.detectors).flat();
    const results: string[][] = [];
    for (let i = 0; i < entries.length; i += 4) {
      results.push(...(await Promise.all(entries.slice(i, i + 4).map(checkPattern))));
    }
    expect(results.flat()).toEqual([]);
  });

  it.each([
    ['newlines', '\n'],
    ['bidi override characters', '\u202A'],
    ['open angle brackets', '<'],
    ['spaces', ' '],
  ])('a full scan of 200,000 %s finishes in under a second', async (_name, ch) => {
    const helper = fileURLToPath(new URL('./fixtures/time-scan.ts', import.meta.url));
    const ms = await new Promise<number>((resolve) => {
      const child = spawn(process.execPath, ['--import', 'tsx', helper, JSON.stringify(ch), '200000'], {
        stdio: ['ignore', 'pipe', 'inherit'],
      });
      let out = '';
      const timer = setTimeout(() => child.kill('SIGKILL'), DEADLINE_MS);
      child.stdout.on('data', (d) => (out += d));
      child.once('close', () => {
        clearTimeout(timer);
        resolve(out === '' ? Infinity : Number(out));
      });
    });
    expect(ms).toBeLessThan(1_000);
  }, 60_000);
});
