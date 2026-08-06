/**
 * Model integrity check — confirms the checksum and label map this package
 * ships still agree with the artifacts actually hosted on HuggingFace.
 *
 * `MODEL_CHECKSUM` is maintained by hand during the model-update lifecycle
 * (retrain -> export -> update checksum -> push to HF -> publish npm). Nothing
 * previously verified that the constant and the hosted file still matched, so
 * drift surfaced only when an end user hit `CHECKSUM_MISMATCH` on download.
 *
 * Run: `npm run check:model` (fast) or `npm run check:model:deep` (downloads).
 * Needs no secrets — the HuggingFace repo is public and this is read-only.
 *
 * ── Why the fast path doesn't download 165MB ──
 * HuggingFace stores large files in LFS and exposes each one's `lfs.oid` via the
 * tree API. That oid IS the file's SHA-256 — verified against real downloaded
 * bytes via `--deep`, which produces an identical digest. So the weekly check is
 * a metadata read, not a large transfer, which is what makes it cheap enough to
 * also gate every npm publish. `--deep` remains available for proof independent
 * of HuggingFace's own metadata.
 *
 * Decision logic lives in `model-integrity.ts` so it is testable without network.
 */

import { createHash } from 'node:crypto';
import { HF_REPO_ID, MODEL_CHECKSUM, MODEL_FILENAME } from '../src/constants';
import {
  checkLabelMap,
  checkModelChecksum,
  checkRequiredFiles,
  checkTokenizer,
  mergeReports,
  type HfTreeEntry,
  type IntegrityReport,
} from './model-integrity';

const TREE_API = `https://huggingface.co/api/models/${HF_REPO_ID}/tree/main`;
const RESOLVE_BASE = `https://huggingface.co/${HF_REPO_ID}/resolve/main`;

async function fetchJson<T>(url: string, label: string): Promise<T> {
  const res = await fetch(url, { redirect: 'follow' });
  if (!res.ok) {
    throw new Error(`${label}: HTTP ${res.status} ${res.statusText} for ${url}`);
  }
  return (await res.json()) as T;
}

/** SHA-256 of a remote file, streamed so a 165MB model never lands in memory. */
async function sha256Remote(url: string): Promise<string> {
  const res = await fetch(url, { redirect: 'follow' });
  if (!res.ok || !res.body) {
    throw new Error(`download failed: HTTP ${res.status} for ${url}`);
  }
  const hash = createHash('sha256');
  for await (const chunk of res.body as unknown as AsyncIterable<Uint8Array>) {
    hash.update(chunk);
  }
  return hash.digest('hex');
}

async function main(): Promise<void> {
  const deep = process.argv.includes('--deep');

  console.log(`Checking ${HF_REPO_ID} against packages/ml constants`);
  console.log(`Mode: ${deep ? 'deep (downloads and hashes real bytes)' : 'fast (LFS oid metadata)'}\n`);

  const tree = await fetchJson<HfTreeEntry[]>(TREE_API, 'tree API');
  const byPath = new Map(tree.map((entry) => [entry.path, entry]));

  const actualDigest = deep
    ? await sha256Remote(`${RESOLVE_BASE}/${MODEL_FILENAME}`)
    : byPath.get(MODEL_FILENAME)?.lfs?.oid;

  let labelReport: IntegrityReport;
  try {
    const labelMap = await fetchJson<Record<string, string>>(
      `${RESOLVE_BASE}/label_map.json`,
      'label_map.json'
    );
    labelReport = checkLabelMap(labelMap);
  } catch (err) {
    labelReport = {
      failures: [`could not read label_map.json: ${err instanceof Error ? err.message : String(err)}`],
      notes: [],
    };
  }

  const { failures, notes } = mergeReports(
    checkRequiredFiles(byPath),
    checkModelChecksum(byPath, MODEL_CHECKSUM, actualDigest, { deep }),
    labelReport,
    checkTokenizer(byPath)
  );

  for (const note of notes) console.log(`  ok   ${note}`);

  if (failures.length > 0) {
    console.error(`\nFAIL — ${failures.length} integrity problem(s):\n`);
    for (const f of failures) console.error(`  - ${f}`);
    console.error(
      `\nIf a retrain intentionally changed the hosted model, update MODEL_CHECKSUM ` +
        `(and MODEL_VERSION, if the label space or tokenizer changed) in ` +
        `packages/ml/src/constants.ts, then re-run.`
    );
    process.exit(1);
  }

  console.log(`\nPASS — hosted artifacts agree with packages/ml/src/constants.ts.`);
}

main().catch((err) => {
  // A network or API failure is not an integrity failure, but it must not pass
  // silently either — unverifiable is still a state we should not publish on.
  console.error(
    `\nERROR — integrity check could not complete: ${err instanceof Error ? err.message : String(err)}`
  );
  process.exit(1);
});
