import { homedir, platform } from 'os';
import { join } from 'path';

export const MODEL_VERSION = 'v3';
export const HF_REPO_ID = 'stylusnexus/agent-armor-classifier';
/**
 * The Hugging Face branch or tag the package downloads from. Pinned so that a
 * newer model pushed to `main` cannot break the checksum of an older package
 * version. A retrain publishes to a new revision and bumps this with
 * MODEL_VERSION and REQUIRED_MODEL_CHECKSUMS in one change.
 */
export const HF_REVISION = 'v3';
export const MODEL_FILENAME = 'model_quantized.onnx';

export const REQUIRED_MODEL_FILES = [
  'model_quantized.onnx',
  'tokenizer.json',
  'label_map.json',
] as const;

export const OPTIONAL_MODEL_FILES = ['tokenizer_config.json', 'special_tokens_map.json'] as const;

export const MODEL_CHECKSUM = '17a4ae95494348929833a5ef8de8007c82d84e4b9c8bf4c53d4530688aec03a0';

/** SHA-256 digests for the required files at HF_REVISION. Update with every model release. */
export const REQUIRED_MODEL_CHECKSUMS: Readonly<
  Record<(typeof REQUIRED_MODEL_FILES)[number], string>
> = {
  'model_quantized.onnx': MODEL_CHECKSUM,
  'tokenizer.json': '2b37df34524d914c6f15ddccdb324c98d43358d5f68a52758fcc87721c3dd16d',
  'label_map.json': 'a4de5af7e74d57145f719c1ed7694943a1e6e4890387216acaa3e9c25c7ac574',
};

/** SHA-256 digests for every required artifact, used to pin custom model directories. */
export type ModelArtifactChecksums = Record<(typeof REQUIRED_MODEL_FILES)[number], string>;

export const LABELS = [
  'hidden-html',
  'metadata-injection',
  'dynamic-cloaking',
  'syntactic-masking',
  'embedded-jailbreak',
  'data-exfiltration',
  'sub-agent-spawning',
  'rag-knowledge-poisoning',
  'latent-memory-poisoning',
  'contextual-learning-trap',
  'biased-framing',
  'oversight-evasion',
  'persona-hyperstition',
  'benign',
] as const;

export const LABEL_TO_INDEX = Object.fromEntries(LABELS.map((label, i) => [label, i])) as Record<
  (typeof LABELS)[number],
  number
>;

export function getDefaultCacheDir(): string {
  const envOverride = process.env.AGENTARMOR_CACHE_DIR;
  if (envOverride) return envOverride;

  const xdg = process.env.XDG_CACHE_HOME;
  if (xdg) return join(xdg, 'agentarmor', MODEL_VERSION);

  if (platform() === 'darwin') {
    return join(homedir(), 'Library', 'Caches', 'agentarmor', MODEL_VERSION);
  }

  return join(homedir(), '.cache', 'agentarmor', MODEL_VERSION);
}

export const DEFAULT_TIMEOUT_MS = 120_000;
export const DEFAULT_RETRIES = 2;
