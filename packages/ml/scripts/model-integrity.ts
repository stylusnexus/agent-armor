/**
 * Decision logic for the model integrity check, kept free of network and
 * process concerns so it can be tested directly.
 *
 * `check-model-integrity.ts` does the fetching, printing and exit code; every
 * judgement about whether the hosted artifacts are acceptable lives here.
 */

import { LABELS, MODEL_FILENAME, REQUIRED_MODEL_FILES } from '../src/constants';

/** One entry from HuggingFace's `/api/models/{repo}/tree/{ref}` response. */
export interface HfTreeEntry {
  path: string;
  size: number;
  lfs?: { oid: string; size: number };
}

export interface IntegrityReport {
  failures: string[];
  notes: string[];
}

/**
 * A tokenizer.json below this is not a plausible WordPiece vocabulary — the real
 * one is ~8.6MB. Catches a truncated or failed upload that still leaves a file
 * behind, which a presence-only check would wave through.
 */
export const MIN_TOKENIZER_BYTES = 100_000;

/** Every required file exists and is non-empty — catches a partial upload. */
export function checkRequiredFiles(byPath: Map<string, HfTreeEntry>): IntegrityReport {
  const failures: string[] = [];
  for (const file of REQUIRED_MODEL_FILES) {
    const entry = byPath.get(file);
    if (!entry) {
      failures.push(`required file "${file}" is missing from the HuggingFace repo`);
    } else if (entry.size === 0) {
      failures.push(`required file "${file}" is present but zero bytes`);
    }
  }
  return { failures, notes: [] };
}

/**
 * The hosted model digest agrees with the checksum this package ships.
 *
 * `actualDigest` is supplied by the caller so the same comparison serves both
 * modes: the fast path passes HuggingFace's LFS oid (which is the file's
 * SHA-256), the deep path passes a digest computed over downloaded bytes.
 */
export function checkModelChecksum(
  byPath: Map<string, HfTreeEntry>,
  expected: string,
  actualDigest: string | undefined,
  { deep }: { deep: boolean }
): IntegrityReport {
  const failures: string[] = [];
  const notes: string[] = [];
  const model = byPath.get(MODEL_FILENAME);

  if (!model) {
    failures.push(`cannot verify checksum: "${MODEL_FILENAME}" not found in the repo`);
    return { failures, notes };
  }

  if (expected.startsWith('PLACEHOLDER')) {
    failures.push(
      `MODEL_CHECKSUM is still a placeholder in packages/ml/src/constants.ts — ` +
        `set it to the hosted digest ${actualDigest ?? '(unavailable)'} before publishing.`
    );
    return { failures, notes };
  }

  if (!actualDigest) {
    failures.push(
      `"${MODEL_FILENAME}" is not stored in LFS, so no oid is available to compare. ` +
        `Re-run with --deep to hash the bytes directly.`
    );
    return { failures, notes };
  }

  if (actualDigest !== expected) {
    failures.push(
      `checksum mismatch on "${MODEL_FILENAME}"${deep ? ' (downloaded bytes)' : ''}:\n` +
        `    hosted  : ${actualDigest}\n` +
        `    expected: ${expected}  (packages/ml/src/constants.ts)\n` +
        `    Either the hosted artifact changed, or a retrain updated HF without updating the constant.`
    );
    return { failures, notes };
  }

  notes.push(
    deep
      ? `${MODEL_FILENAME} digest verified over ${model.size.toLocaleString()} downloaded bytes`
      : `${MODEL_FILENAME} checksum matches (${model.size.toLocaleString()} bytes)`
  );
  return { failures, notes };
}

/**
 * The hosted label map must match `LABELS` index for index, not merely as a set.
 *
 * The ONNX model emits one sigmoid output per index. If a retrain reorders the
 * label space, every index silently means something different — the classifier
 * mislabels everything while still looking perfectly healthy.
 */
export function checkLabelMap(hosted: Record<string, string>): IntegrityReport {
  const failures: string[] = [];
  const notes: string[] = [];
  const hostedCount = Object.keys(hosted).length;

  if (hostedCount !== LABELS.length) {
    failures.push(
      `label_map.json has ${hostedCount} labels, package expects ${LABELS.length}. ` +
        `A label-space change requires a retrain and a MODEL_VERSION bump, not just a checksum update.`
    );
    return { failures, notes };
  }

  const mismatched = LABELS.map((label, index) => ({
    index,
    label,
    hosted: hosted[String(index)],
  })).filter((entry) => entry.hosted !== entry.label);

  if (mismatched.length > 0) {
    failures.push(
      `label_map.json disagrees with LABELS at ${mismatched.length} index(es):\n` +
        mismatched
          .map((m) => `    index ${m.index}: hosted "${m.hosted}" vs package "${m.label}"`)
          .join('\n') +
        `\n    Index order defines what each ONNX output means — a mismatch mislabels silently.`
    );
    return { failures, notes };
  }

  notes.push(`label_map.json matches all ${LABELS.length} labels in order`);
  return { failures, notes };
}

/** tokenizer.json is present and plausibly complete rather than truncated. */
export function checkTokenizer(byPath: Map<string, HfTreeEntry>): IntegrityReport {
  const failures: string[] = [];
  const notes: string[] = [];
  const tokenizer = byPath.get('tokenizer.json');

  if (!tokenizer) return { failures, notes }; // absence already reported by checkRequiredFiles

  if (tokenizer.size < MIN_TOKENIZER_BYTES) {
    failures.push(
      `tokenizer.json is only ${tokenizer.size} bytes — implausibly small for a WordPiece vocab, ` +
        `suggesting a truncated or failed upload.`
    );
  } else {
    notes.push(`tokenizer.json present (${tokenizer.size.toLocaleString()} bytes)`);
  }

  return { failures, notes };
}

export function mergeReports(...reports: IntegrityReport[]): IntegrityReport {
  return {
    failures: reports.flatMap((r) => r.failures),
    notes: reports.flatMap((r) => r.notes),
  };
}
