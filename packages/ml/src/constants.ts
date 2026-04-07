import { homedir, platform } from 'os';
import { join } from 'path';

export const MODEL_VERSION = 'v1';
export const HF_REPO_ID = 'stylusnexus/agent-armor-classifier';
export const MODEL_FILENAME = 'model_quantized.onnx';

export const REQUIRED_MODEL_FILES = [
  'model_quantized.onnx',
  'tokenizer.json',
  'label_map.json',
] as const;

export const OPTIONAL_MODEL_FILES = [
  'tokenizer_config.json',
  'special_tokens_map.json',
] as const;

export const MODEL_CHECKSUM = '5d4c8551c958f398181c60239aebedbaa4ed5b641d1645904d2de9c2d02bd41f';

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

export const LABEL_TO_INDEX = Object.fromEntries(
  LABELS.map((label, i) => [label, i])
) as Record<(typeof LABELS)[number], number>;

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
