/**
 * Child-process helper for pattern-time-budget.test.ts. Reads
 * `{ entry, units, steps }` as JSON on stdin and prints the list of
 * budget violations as JSON. It runs each pattern the way `PatternDetector`
 * does: through its hand-written matcher when one is bound to the pattern's
 * exact regex, otherwise through the regex itself. It lives in its own
 * process so the test can kill it when a slow pattern never returns.
 */
import { findMatcher } from '../../patterns/matchers';

interface Entry {
  id: string;
  regex: string;
  flags: string;
  extractGroup?: number;
}
interface Step {
  chars: number;
  budgetMs: number;
}

let input = '';
process.stdin.on('data', (d) => (input += d));
process.stdin.on('end', () => {
  const { entry, units, steps } = JSON.parse(input) as { entry: Entry; units: string[]; steps: Step[] };
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
  const slow: string[] = [];
  for (const unit of units) {
    for (const { chars, budgetMs } of steps) {
      const text = unit.repeat(Math.ceil(chars / unit.length));
      const start = performance.now();
      run(text);
      const ms = performance.now() - start;
      if (ms > budgetMs) {
        slow.push(`${entry.id}: ${Math.round(ms)}ms > ${budgetMs}ms on ${text.length} chars of ${JSON.stringify(unit.slice(0, 40))}`);
        break;
      }
    }
  }
  process.stdout.write(JSON.stringify(slow));
});
