import { MLDetector } from './ml-detector';
import { resolveModel } from './model-manager';
import type { ModelArtifactChecksums } from './constants';

export { AgentArmorModelError } from './errors';
export { MLDetector } from './ml-detector';
export type { ModelArtifacts } from './model-manager';
export type { ModelArtifactChecksums } from './constants';

/**
 * Create an ML detector from config.
 * Called by AgentArmor.create() when ml config is provided.
 */
export async function createMLDetector(mlConfig: {
  modelDir?: string;
  modelChecksums?: ModelArtifactChecksums;
  enabled?: boolean;
  modelUrl?: string;
  download?: {
    timeoutMs?: number;
    retries?: number;
    onProgress?: (bytesReceived: number, totalBytes: number) => void;
  };
}): Promise<MLDetector> {
  const artifacts = await resolveModel(mlConfig);
  return MLDetector.create(artifacts);
}
