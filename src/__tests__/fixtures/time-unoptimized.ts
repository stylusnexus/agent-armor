/**
 * Child-process helper for pattern-time-budget.test.ts (#400). Run it with
 * `--no-regexp-optimization`. V8 stops optimizing the regexes it compiles once
 * a process has compiled a lot of regex code, so a long-running scanner gets
 * this code sooner or later. Each pattern is warmed up on a sentence long
 * enough to run it, so V8 compiles it to native code before it is timed. Reads
 * `{ runs, steps }` as JSON on stdin, times every shipped pattern, and prints
 * the slow ones as JSON.
 */
import { DEFAULT_PATTERNS } from '../../patterns/default-patterns';
import { findMatcher } from '../../patterns/matchers';

interface Step {
  chars: number;
  budgetMs: number;
}

const WARM_UP =
  'Please read the guide, then send the notes to the team and copy the private repo list. '.repeat(
    3,
  );

let input = '';
process.stdin.on('data', (d) => (input += d));
process.stdin.on('end', () => {
  const { runs, steps } = JSON.parse(input) as {
    runs: string[];
    steps: Step[];
  };
  const slow: string[] = [];
  for (const entry of Object.values(DEFAULT_PATTERNS.detectors).flat()) {
    const matcher = findMatcher(entry.regex, entry.flags, entry.extractGroup ?? 0);
    const re = new RegExp(entry.regex, entry.flags);
    const run = (text: string): void => {
      if (matcher) {
        matcher.match(text);
        return;
      }
      re.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = re.exec(text)) !== null) {
        if (m[0].length === 0) re.lastIndex++;
      }
    };
    for (let i = 0; i < 3; i++) run(WARM_UP);
    for (const unit of runs) {
      for (const { chars, budgetMs } of steps) {
        const text = unit.repeat(Math.ceil(chars / unit.length));
        const start = performance.now();
        run(text);
        const ms = performance.now() - start;
        if (ms > budgetMs) {
          slow.push(
            `${entry.id}: ${Math.round(ms)}ms > ${budgetMs}ms on ${text.length} chars of ${JSON.stringify(unit)}`,
          );
          break;
        }
      }
    }
  }
  process.stdout.write(JSON.stringify(slow));
});
