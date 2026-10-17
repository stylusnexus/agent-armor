import { Worker } from 'node:worker_threads';
import { DEFAULT_PATTERNS } from './default-patterns';
import type { PatternEntry } from './pattern-db';

/** Thrown when a pattern database fails validation. `problems` lists every failure found. */
export class PatternValidationError extends Error {
  readonly problems: string[];

  constructor(problems: string[]) {
    const shown = problems.slice(0, 10).join('; ');
    const more = problems.length > 10 ? ` (and ${problems.length - 10} more)` : '';
    super(`Invalid pattern database: ${shown}${more}`);
    this.name = 'PatternValidationError';
    this.problems = problems;
  }
}

const CATEGORIES = new Set([
  'content-injection',
  'semantic-manipulation',
  'cognitive-state',
  'behavioural-control',
  'systemic',
  'human-in-the-loop',
  'transport-integrity',
]);
const SEVERITIES = new Set(['low', 'medium', 'high', 'critical']);
const KNOWN_FLAGS = /^[dgimsuvy]*$/;

/** Lowest confidence that still reports at `balanced`, the default strictness. */
const BALANCED_THRESHOLD = 0.5;
/** Added to a boost-eligible pattern's confidence when instruction signals are present. */
const BOOST = 0.35;

/** Probe length and per-probe limit for the speed check. */
const PROBE_CHARS = 20_000;
const PROBE_LIMIT_MS = 200;
/** The whole speed check, including worker start-up, gets this long. */
const SPEED_CHECK_TIMEOUT_MS = 10_000;

/** Inputs a zero-width match is looked for in. */
const EMPTY_PROBES = ['', ' ', 'a', 'x y', '\n', '<a>', '1'];

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function reachesBalanced(entry: PatternEntry): boolean {
  const best = entry.boostOnInstructions ? Math.min(entry.confidence + BOOST, 1) : entry.confidence;
  return best >= BALANCED_THRESHOLD;
}

function entryKey(regex: string, flags: string, extractGroup: number | undefined): string {
  return `${flags}\u0000${extractGroup ?? 0}\u0000${regex}`;
}

/** Entries identical to a shipped one are already covered by the repo's own time-budget test. */
const SHIPPED_ENTRY_KEYS = new Set(
  Object.values(DEFAULT_PATTERNS.detectors).flatMap((entries) =>
    entries.map((e) => entryKey(e.regex, e.flags, e.extractGroup)),
  ),
);

/** Check one entry's shape. Returns the compiled regex when it is usable. */
function checkEntry(
  detectorId: string,
  entry: unknown,
  index: number,
  seenIds: Set<string>,
  problems: string[],
): PatternEntry | undefined {
  const where = `${detectorId}[${index}]`;
  if (!isRecord(entry)) {
    problems.push(`${where}: pattern is not an object`);
    return undefined;
  }
  const e = entry as Record<string, unknown>;
  const label = typeof e.id === 'string' && e.id ? `${detectorId}/${e.id}` : where;
  let ok = true;
  const bad = (msg: string): void => {
    problems.push(`${label}: ${msg}`);
    ok = false;
  };

  if (typeof e.id !== 'string' || !e.id) bad('id must be a non-empty string');
  else if (seenIds.has(e.id)) bad('duplicate pattern id');
  else seenIds.add(e.id);
  if (typeof e.label !== 'string') bad('label must be a string');
  if (typeof e.regex !== 'string' || !e.regex) bad('regex must be a non-empty string');
  if (typeof e.flags !== 'string') bad('flags must be a string');
  else if (!KNOWN_FLAGS.test(e.flags)) bad(`flags "${e.flags}" has an unknown flag`);
  else if (!e.flags.includes('g')) {
    bad('flags must include "g" (a global scan loop never advances without it)');
  }
  if (typeof e.category !== 'string' || !CATEGORIES.has(e.category)) {
    bad('category is not a known trap category');
  }
  if (typeof e.type !== 'string' || !e.type) bad('type must be a non-empty string');
  if (typeof e.severity !== 'string' || !SEVERITIES.has(e.severity)) {
    bad('severity must be low, medium, high or critical');
  }
  if (typeof e.confidence !== 'number' || !(e.confidence >= 0 && e.confidence <= 1)) {
    bad('confidence must be a number from 0 to 1');
  }
  if (e.scope !== undefined && e.scope !== 'tool-call-command') {
    bad('scope must be omitted or "tool-call-command"');
  }
  for (const key of ['boostOnInstructions', 'requireInstructions'] as const) {
    if (e[key] !== undefined && typeof e[key] !== 'boolean') bad(`${key} must be a boolean`);
  }
  for (const key of ['extractGroup', 'minLength'] as const) {
    const v = e[key];
    if (v !== undefined && !(typeof v === 'number' && Number.isInteger(v) && v >= 0)) {
      bad(`${key} must be a non-negative integer`);
    }
  }
  if (!ok) return undefined;

  const pattern = e as unknown as PatternEntry;
  let regex: RegExp;
  try {
    regex = new RegExp(pattern.regex, pattern.flags);
  } catch (err) {
    bad(`regex does not compile: ${err instanceof Error ? err.message : String(err)}`);
    return undefined;
  }
  const groups = (new RegExp(`${pattern.regex}|`, pattern.flags).exec('') ?? []).length - 1;
  if ((pattern.extractGroup ?? 0) > groups) {
    bad(`extractGroup ${pattern.extractGroup} is past the ${groups} capture groups in the regex`);
    return undefined;
  }
  for (const probe of EMPTY_PROBES) {
    regex.lastIndex = 0;
    const m = regex.exec(probe);
    if (m && m[0].length === 0) {
      bad('regex can match empty text (a global scan loop would never advance)');
      return undefined;
    }
  }
  return pattern;
}

/** Runs in a worker so a regex that never finishes can be killed instead of freezing the caller. */
const SPEED_WORKER = `
const { parentPort, workerData } = require('node:worker_threads');
const FRAGMENTS = [' ', '\\n', '\\t', 'a', '0', '<', '>', '-', '.', '"', "'", '\\\\', 'a ', 'ab', '<a ', '&#', '\\u200b'];
const slow = [];
for (const { id, regex, flags } of workerData.entries) {
  parentPort.postMessage({ started: id });
  const re = new RegExp(regex, flags);
  probes: for (const fragment of FRAGMENTS) {
    const run = fragment.repeat(Math.ceil(workerData.chars / fragment.length)).slice(0, workerData.chars);
    // The bare run, then the run followed by a character that ends it, so a match that was building up fails late.
    for (const text of [run, run + '!']) {
      const t0 = performance.now();
      re.lastIndex = 0;
      while (re.exec(text) !== null) { /* each match advances: empty matches were rejected */ }
      const ms = performance.now() - t0;
      if (ms > workerData.limitMs) { slow.push({ id, ms: Math.round(ms), probe: JSON.stringify(fragment) }); break probes; }
    }
  }
}
parentPort.postMessage({ done: true, slow });
`;

/**
 * Run each regex against fixed-size adversarial probes in a worker thread and
 * report the ones that are slow. A regex that never finishes is caught by
 * terminating the worker, and is named from the last pattern it started.
 */
function checkSpeed(entries: PatternEntry[], problems: string[]): Promise<void> {
  if (entries.length === 0) return Promise.resolve();
  return new Promise((resolve) => {
    const worker = new Worker(SPEED_WORKER, {
      eval: true,
      workerData: {
        entries: entries.map((e) => ({ id: e.id, regex: e.regex, flags: e.flags })),
        chars: PROBE_CHARS,
        limitMs: PROBE_LIMIT_MS,
      },
    });
    let current = '';
    let finished = false;
    const finish = (): void => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      void worker.terminate();
      resolve();
    };
    const timer = setTimeout(() => {
      problems.push(
        `${current || 'speed check'}: regex did not finish on a ${PROBE_CHARS}-character probe ` +
          `within ${SPEED_CHECK_TIMEOUT_MS / 1000}s`,
      );
      finish();
    }, SPEED_CHECK_TIMEOUT_MS);
    worker.on('message', (msg: { started?: string; done?: boolean; slow?: unknown[] }) => {
      if (msg.started) current = msg.started;
      if (msg.done) {
        for (const s of (msg.slow ?? []) as Array<{ id: string; ms: number; probe: string }>) {
          problems.push(
            `${s.id}: regex took ${s.ms} ms on a ${PROBE_CHARS}-character probe of ${s.probe} ` +
              `(limit ${PROBE_LIMIT_MS} ms); it may backtrack badly`,
          );
        }
        finish();
      }
    });
    worker.on('error', (err: Error) => {
      problems.push(`speed check failed: ${err.message}`);
      finish();
    });
  });
}

/**
 * Validate a pattern database before it is loaded. Throws `PatternValidationError`
 * listing every problem found; resolves when the database is safe to load.
 *
 * Checks: the shape of every field; the `g` flag; regexes that compile and
 * cannot match empty text; every detector the package ships is still present
 * and keeps at least one pattern that reports at `balanced` (so a file cannot
 * silently turn detection off); and a speed check of each regex that is not
 * identical to a shipped one.
 *
 * The speed check runs each new regex against fixed probes (20,000 characters of
 * one repeated fragment, bare and followed by a stop character) and rejects any over 200 ms or that never finishes.
 * It catches exponential and clearly quadratic regexes. It cannot prove a regex
 * is linear: a regex that is slow only on input shaped like its own trigger
 * wording can pass. Review new patterns as well.
 */
export async function validatePatternDatabase(db: unknown): Promise<void> {
  const problems: string[] = [];
  if (!isRecord(db)) throw new PatternValidationError(['database is not an object']);
  if (typeof db.version !== 'string' || !db.version)
    problems.push('version must be a non-empty string');
  if (typeof db.updatedAt !== 'string') problems.push('updatedAt must be a string');
  if (!isRecord(db.detectors)) {
    problems.push('detectors must be an object of pattern lists');
    throw new PatternValidationError(problems);
  }

  const seenIds = new Set<string>();
  const needSpeedCheck: PatternEntry[] = [];
  const valid: Record<string, PatternEntry[]> = {};
  for (const [detectorId, list] of Object.entries(db.detectors)) {
    if (!Array.isArray(list)) {
      problems.push(`${detectorId}: patterns must be an array`);
      continue;
    }
    valid[detectorId] = [];
    list.forEach((entry, i) => {
      const checked = checkEntry(detectorId, entry, i, seenIds, problems);
      if (!checked) return;
      valid[detectorId].push(checked);
      if (!SHIPPED_ENTRY_KEYS.has(entryKey(checked.regex, checked.flags, checked.extractGroup))) {
        needSpeedCheck.push(checked);
      }
    });
  }

  for (const [detectorId, shipped] of Object.entries(DEFAULT_PATTERNS.detectors)) {
    if (!(detectorId in valid)) {
      problems.push(`${detectorId}: shipped detector is missing`);
    } else if (shipped.some(reachesBalanced) && !valid[detectorId].some(reachesBalanced)) {
      problems.push(
        `${detectorId}: no valid pattern reports at balanced strictness (confidence 0.5 or more)`,
      );
    }
  }

  if (problems.length === 0) await checkSpeed(needSpeedCheck, problems);
  if (problems.length > 0) throw new PatternValidationError(problems);
}
