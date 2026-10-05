/**
 * Child-process helper for pattern-time-budget.test.ts: prints how many
 * milliseconds `scanSync` takes on `chars` repeats of a fragment. It runs in
 * its own process so the test can kill it if a slow pattern never returns.
 * Usage: node --import tsx time-scan.ts <fragment-as-JSON-string> <chars>
 */
import { AgentArmor } from '../../agent-armor';

const fragment = JSON.parse(process.argv[2]) as string;
const chars = Number(process.argv[3]);
const armor = AgentArmor.regexOnly();
const start = performance.now();
armor.scanSync(fragment.repeat(Math.ceil(chars / fragment.length)));
process.stdout.write(String(performance.now() - start));
