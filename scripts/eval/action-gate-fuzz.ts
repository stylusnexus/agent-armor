/**
 * Action-gate fuzz eval — SecLists LFI/traversal corpus vs the pre-execution gate.
 *
 * The unit tests in `src/__tests__/action-gate.test.ts` prove the gate blocks a
 * handful of hand-written traversal cases. This eval turns that into a real
 * fuzz: it replays every payload in the SecLists `Fuzzing/LFI` corpus (each in
 * raw + URL-decoded forms) through the actual `evaluateAction()` and asserts a
 * pinned baseline of ZERO workspace escapes.
 *
 * Scoring by ESCAPES, not raw admits
 * ----------------------------------
 * An LFI wordlist conflates two different things: genuine *escape payloads*
 * (`/etc/passwd`, `../../etc/passwd`, encoded variants) and bare *in-workspace
 * filenames* (`config.php`, `etc/passwd` as a relative path). The gate is a
 * confinement primitive: it is SUPPOSED to admit a relative in-workspace read
 * and SUPPOSED to deny anything that climbs out. So "admitted" is the wrong
 * metric — admitting `config.php` is correct, not a bug.
 *
 * The metric that matters is an ESCAPE: a payload that, taken literally as the
 * already-decoded path the gate's contract requires, targets a location OUTSIDE
 * a confined workspace root, yet is admitted. `escapesWorkspace()` decides
 * "targets outside root" independently of the gate (absolute/drive paths, or a
 * relative path that normalizes above the root), so the assertion is not
 * tautological — we count real escape attempts and verify each was denied.
 *
 * Baseline: ESCAPE_BASELINE = 0. Any admitted escape fails the eval (exit 1),
 * the same regression-gate role `thresholds.json` plays for detection rates.
 *
 * Skips cleanly (exit 0) when the SecLists corpus is not present, so it never
 * breaks CI on a machine without it. Point it at a corpus with SECLISTS_DIR.
 *
 * Usage: npx tsx scripts/eval/action-gate-fuzz.ts
 *        SECLISTS_DIR=/path/to/SecLists npx tsx scripts/eval/action-gate-fuzz.ts
 */

import { readFileSync, readdirSync, existsSync, statSync } from 'node:fs';
import path from 'node:path';
import { evaluateAction } from '../../src/action-gate';
import type { ActionRule } from '../../src/types';

/** Pinned regression baseline: the gate must never admit a workspace escape. */
const ESCAPE_BASELINE = 0;

/**
 * The most adversarial allowlist possible for isolating the traversal defence:
 * read anything in the workspace, read-only. With `**​/*` there is no narrowing
 * glob to also catch a payload — the gate's path policy (absolute / traversal /
 * percent-encoding / non-ASCII) is the only thing standing between a payload and
 * admission, so any escape is purely a path-policy failure.
 */
const RULES: ActionRule[] = [{ tool: 'read_file', paths: ['**/*'], mode: 'read-only' }];

const ROOT = '/__agentarmor_sandbox_root__';

/** Treat a backslash as a path separator (Windows form) for literal reasoning. */
function toPosix(p: string): string {
  return p.replace(/\\/g, '/');
}

function isAbsoluteLike(p: string): boolean {
  return /^[\\/]/.test(p) || /^[A-Za-z]:[\\/]?/.test(p);
}

/**
 * Does this path, taken literally as a decoded path, target a location outside a
 * confined workspace root? Absolute/drive paths escape by definition; a relative
 * path escapes if it normalizes to something not under ROOT (i.e. it climbs out
 * via `..`). Bare in-workspace filenames (`config.php`, relative `etc/passwd`)
 * do NOT escape — admitting those is correct gate behaviour.
 */
function escapesWorkspace(rawPath: string): boolean {
  if (isAbsoluteLike(rawPath)) return true;
  const resolved = path.posix.normalize(path.posix.join(ROOT, toPosix(rawPath)));
  return resolved !== ROOT && !resolved.startsWith(ROOT + '/');
}

/** Single-pass %XX decode, for payloads decodeURIComponent rejects as malformed. */
function manualDecode(s: string): string {
  return s.replace(/%([0-9a-fA-F]{2})/g, (_, h: string) => String.fromCharCode(parseInt(h, 16)));
}

/** The gate's contract is "already-decoded path"; SecLists ships encoded forms.
 * Test raw (should die on the `%` rule) and the decoded form (the real test). */
function forms(raw: string): { label: string; path: string }[] {
  const out = [{ label: 'raw', path: raw }];
  try {
    const d = decodeURIComponent(raw);
    if (d !== raw) out.push({ label: 'decodeURI', path: d });
  } catch {
    const d = manualDecode(raw);
    if (d !== raw) out.push({ label: 'manual%XX', path: d });
  }
  return out;
}

function findCorpus(): string | null {
  const candidates = [
    process.env.SECLISTS_DIR,
    path.resolve(process.cwd(), '../SecLists'),
    path.resolve(process.cwd(), '../../SecLists'),
  ].filter((c): c is string => Boolean(c));
  for (const dir of candidates) {
    if (existsSync(path.join(dir, 'Fuzzing', 'LFI'))) return dir;
  }
  return null;
}

function collectTxt(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...collectTxt(full));
    else if (entry.isFile() && entry.name.endsWith('.txt')) out.push(full);
  }
  return out;
}

function bucket(reason: string): string {
  if (reason.includes('percent-encoding')) return 'percent-encoding';
  if (reason.includes('non-ASCII')) return 'non-ASCII';
  if (reason.includes('absolute')) return 'absolute path';
  if (reason.includes('parent-directory')) return 'traversal (..)';
  if (reason.includes('outside the allowed')) return 'glob mismatch';
  return 'other';
}

function main(): void {
  const corpus = findCorpus();
  if (!corpus) {
    console.log('\n[action-gate-fuzz] SecLists corpus not found — skipping.');
    console.log('  Set SECLISTS_DIR=/path/to/SecLists (needs Fuzzing/LFI/).\n');
    process.exit(0);
  }

  const lfiDir = path.join(corpus, 'Fuzzing', 'LFI');
  const files = collectTxt(lfiDir);

  let formsTested = 0;
  let escapeAttempts = 0; // forms that genuinely target outside the workspace
  let inWorkspaceAdmits = 0; // correct admits of in-workspace relative reads
  const escapes: { payload: string; form: string; file: string }[] = [];
  const denials: Record<string, number> = {};

  for (const file of files) {
    let lines: string[];
    try {
      lines = readFileSync(file, 'utf8').split('\n');
    } catch {
      continue;
    }
    for (const line of lines) {
      const raw = line.trim();
      if (!raw) continue;
      for (const { label, path: p } of forms(raw)) {
        formsTested++;
        const attempt = escapesWorkspace(p);
        if (attempt) escapeAttempts++;
        const verdict = evaluateAction({ tool: 'read_file', args: { path: p } }, RULES);
        if (verdict.admissible) {
          if (attempt) {
            escapes.push({ payload: raw, form: label, file: path.relative(corpus, file) });
          } else {
            inWorkspaceAdmits++;
          }
        } else {
          const b = bucket(verdict.reason ?? '');
          denials[b] = (denials[b] ?? 0) + 1;
        }
      }
    }
  }

  console.log('\n=== Action-gate fuzz — SecLists LFI corpus ===\n');
  console.log(`Corpus:           ${path.relative(process.cwd(), lfiDir)} (${files.length} files)`);
  console.log(`Payload-forms:    ${formsTested}`);
  console.log(`Escape attempts:  ${escapeAttempts}  (forms that target outside the workspace)`);
  console.log(`In-workspace admits (correct): ${inWorkspaceAdmits}`);
  console.log('\nDenials by which rule fired:');
  for (const [k, n] of Object.entries(denials).sort((a, b) => b[1] - a[1])) {
    console.log(`  ${k.padEnd(18)} ${n}`);
  }

  console.log(`\nESCAPES (admitted escape attempts): ${escapes.length}  | baseline: ${ESCAPE_BASELINE}`);
  if (escapes.length > ESCAPE_BASELINE) {
    console.log('\n!! REGRESSION — the gate admitted a payload that escapes the workspace:');
    for (const e of escapes.slice(0, 40)) {
      console.log(`  [${e.form}] ${JSON.stringify(e.payload)}  (${e.file})`);
    }
    console.log('\nFAIL: escape baseline exceeded.\n');
    process.exit(1);
  }

  console.log(
    `\nPASS: 0 workspace escapes across ${escapeAttempts} escape attempts ` +
      `(${formsTested} payload-forms).\n`
  );
  process.exit(0);
}

main();
