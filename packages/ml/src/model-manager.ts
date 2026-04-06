import { createHash } from 'crypto';
import { createReadStream, createWriteStream } from 'fs';
import { access, mkdir, open, rename, rm, stat, unlink } from 'fs/promises';
import { get as httpsGet } from 'https';
import { join } from 'path';
import { pipeline } from 'stream/promises';

import {
  DEFAULT_RETRIES,
  DEFAULT_TIMEOUT_MS,
  HF_REPO_ID,
  MODEL_CHECKSUM,
  MODEL_FILENAME,
  OPTIONAL_MODEL_FILES,
  REQUIRED_MODEL_FILES,
  getDefaultCacheDir,
} from './constants';
import { AgentArmorModelError } from './errors';

export interface ModelArtifacts {
  modelPath: string;
  tokenizerPath: string;
  labelMapPath: string;
  modelDir: string;
}

interface MLConfigLike {
  modelDir?: string;
  enabled?: boolean;
  modelUrl?: string;
  download?: {
    timeoutMs?: number;
    retries?: number;
    onProgress?: (bytesReceived: number, totalBytes: number) => void;
  };
}

function artifactsFrom(dir: string): ModelArtifacts {
  return {
    modelPath: join(dir, MODEL_FILENAME),
    tokenizerPath: join(dir, 'tokenizer.json'),
    labelMapPath: join(dir, 'label_map.json'),
    modelDir: dir,
  };
}

/**
 * Validate that all required model files exist in a directory.
 * Throws AgentArmorModelError('MODEL_NOT_FOUND') with a helpful message if any are missing.
 */
export async function validateModelDir(dir: string): Promise<void> {
  const missing: string[] = [];
  for (const file of REQUIRED_MODEL_FILES) {
    try {
      await access(join(dir, file));
    } catch {
      missing.push(file);
    }
  }
  if (missing.length > 0) {
    throw new AgentArmorModelError(
      'MODEL_NOT_FOUND',
      `Missing required model files in ${dir}: ${missing.join(', ')}. ` +
        `Required files: ${REQUIRED_MODEL_FILES.join(', ')}`,
    );
  }
}

/**
 * Resolve model artifacts — either from a user-provided modelDir or from the cache.
 * Downloads from HuggingFace if not cached.
 */
export async function resolveModel(config: MLConfigLike = {}): Promise<ModelArtifacts> {
  const modelDir = config.modelDir || process.env.AGENTARMOR_MODEL_DIR;

  if (modelDir) {
    await validateModelDir(modelDir);
    return artifactsFrom(modelDir);
  }

  const cacheDir = getDefaultCacheDir();
  await mkdir(cacheDir, { recursive: true });

  // Check if a valid cached model exists
  try {
    await validateModelDir(cacheDir);
    return artifactsFrom(cacheDir);
  } catch {
    // Not cached — download
  }

  await downloadWithLock(cacheDir, config);
  return artifactsFrom(cacheDir);
}

/**
 * Acquire a lock file, download all model files, verify checksum, then release the lock.
 * If another process holds the lock, wait for it.
 */
export async function downloadWithLock(
  cacheDir: string,
  config: MLConfigLike,
): Promise<void> {
  const lockPath = join(cacheDir, 'model.onnx.lock');

  let lockFd;
  try {
    lockFd = await open(lockPath, 'wx');
  } catch (err: unknown) {
    if ((err as NodeJS.ErrnoException).code === 'EEXIST') {
      await waitForLock(lockPath, config);
      // After lock is released, check if model is now valid
      try {
        await validateModelDir(cacheDir);
        return;
      } catch {
        // Still missing — acquire lock and download ourselves
        lockFd = await open(lockPath, 'wx');
      }
    } else {
      throw err;
    }
  }

  try {
    // Download required files
    for (const file of REQUIRED_MODEL_FILES) {
      await downloadFile(file, cacheDir, config, false);
    }

    // Download optional files (silently skip on 404)
    for (const file of OPTIONAL_MODEL_FILES) {
      await downloadFile(file, cacheDir, config, true);
    }

    // Verify checksum of the main model file
    const modelPath = join(cacheDir, MODEL_FILENAME);
    const checksumOk = await verifyChecksum(modelPath);
    if (!checksumOk) {
      // Clean up the bad download
      for (const file of REQUIRED_MODEL_FILES) {
        await unlink(join(cacheDir, file)).catch(() => {});
      }
      throw new AgentArmorModelError(
        'CHECKSUM_MISMATCH',
        `Model file checksum verification failed for ${modelPath}`,
      );
    }
  } finally {
    await lockFd.close();
    await unlink(lockPath).catch(() => {});
  }
}

/**
 * Download a single file from HuggingFace (or custom modelUrl) to destDir.
 * Downloads to a .tmp file, then atomically renames on success.
 * Retries with exponential backoff. Optional files return silently on 404.
 */
export async function downloadFile(
  filename: string,
  destDir: string,
  config: MLConfigLike,
  optional: boolean,
): Promise<void> {
  const retries = config.download?.retries ?? DEFAULT_RETRIES;
  const timeoutMs = config.download?.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const onProgress = config.download?.onProgress;

  let baseUrl: string;
  if (config.modelUrl) {
    baseUrl = config.modelUrl.replace(/\/$/, '');
  } else {
    baseUrl = `https://huggingface.co/${HF_REPO_ID}/resolve/main`;
  }

  const url = `${baseUrl}/${filename}`;
  const destPath = join(destDir, filename);
  const tmpPath = `${destPath}.tmp`;

  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      await new Promise<void>((resolve, reject) => {
        const timer = setTimeout(() => {
          reject(
            new AgentArmorModelError(
              'DOWNLOAD_TIMEOUT',
              `Download of ${filename} timed out after ${timeoutMs}ms`,
            ),
          );
        }, timeoutMs);

        const makeRequest = (requestUrl: string, redirectCount = 0): void => {
          if (redirectCount > 5) {
            clearTimeout(timer);
            reject(new AgentArmorModelError('DOWNLOAD_FAILED', `Too many redirects for ${filename}`));
            return;
          }

          const protocol = requestUrl.startsWith('https') ? httpsGet : httpsGet;
          const req = protocol(requestUrl, (res) => {
            if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
              makeRequest(res.headers.location, redirectCount + 1);
              return;
            }

            if (res.statusCode === 404 && optional) {
              clearTimeout(timer);
              res.resume();
              resolve();
              return;
            }

            if (res.statusCode !== 200) {
              clearTimeout(timer);
              res.resume();
              reject(
                new AgentArmorModelError(
                  'DOWNLOAD_FAILED',
                  `Failed to download ${filename}: HTTP ${res.statusCode}`,
                ),
              );
              return;
            }

            const totalBytes = parseInt(res.headers['content-length'] || '0', 10);
            let receivedBytes = 0;

            if (onProgress) {
              res.on('data', (chunk: Buffer) => {
                receivedBytes += chunk.length;
                onProgress(receivedBytes, totalBytes);
              });
            }

            const ws = createWriteStream(tmpPath);
            pipeline(res, ws)
              .then(() => {
                clearTimeout(timer);
                resolve();
              })
              .catch((pipeErr) => {
                clearTimeout(timer);
                reject(
                  new AgentArmorModelError('DOWNLOAD_FAILED', `Failed to write ${filename}`, pipeErr),
                );
              });
          });

          req.on('error', (reqErr) => {
            clearTimeout(timer);
            reject(
              new AgentArmorModelError('DOWNLOAD_FAILED', `Network error downloading ${filename}`, reqErr),
            );
          });
        };

        makeRequest(url);
      });

      // Atomic rename
      await rename(tmpPath, destPath);
      return;
    } catch (err) {
      // Clean up tmp file on failure
      await unlink(tmpPath).catch(() => {});

      if (err instanceof AgentArmorModelError && err.code === 'DOWNLOAD_TIMEOUT') {
        throw err;
      }

      // If optional and this was a 404-like error, just return
      if (optional && err instanceof AgentArmorModelError && err.code === 'DOWNLOAD_FAILED') {
        return;
      }

      if (attempt < retries) {
        // Exponential backoff: 1s, 2s, 4s...
        const delay = 1000 * Math.pow(2, attempt);
        await new Promise((r) => setTimeout(r, delay));
        continue;
      }

      throw err;
    }
  }
}

/**
 * Verify SHA-256 checksum of a file against MODEL_CHECKSUM.
 * Returns true if checksum matches. Skips (returns true) if checksum is a placeholder.
 */
export async function verifyChecksum(filePath: string): Promise<boolean> {
  if (MODEL_CHECKSUM.startsWith('PLACEHOLDER')) {
    return true;
  }

  const hash = createHash('sha256');
  const stream = createReadStream(filePath);
  for await (const chunk of stream) {
    hash.update(chunk);
  }
  const digest = hash.digest('hex');
  return digest === MODEL_CHECKSUM;
}

/**
 * Wait for a lock file to be released by another process.
 * Polls every 2 seconds. Breaks stale lock after timeout.
 */
export async function waitForLock(lockPath: string, config: MLConfigLike): Promise<void> {
  const timeoutMs = config.download?.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const pollInterval = 2000;
  const startTime = Date.now();

  while (Date.now() - startTime < timeoutMs) {
    try {
      await access(lockPath);
    } catch {
      // Lock file gone — we can proceed
      return;
    }

    // Check for stale lock (older than timeout)
    try {
      const lockStat = await stat(lockPath);
      const lockAge = Date.now() - lockStat.mtimeMs;
      if (lockAge > timeoutMs) {
        // Stale lock — break it
        await unlink(lockPath).catch(() => {});
        return;
      }
    } catch {
      // Lock disappeared while checking — that's fine
      return;
    }

    await new Promise((r) => setTimeout(r, pollInterval));
  }

  // Timed out waiting — break the stale lock
  await unlink(lockPath).catch(() => {});
  throw new AgentArmorModelError(
    'LOCK_TIMEOUT',
    `Timed out waiting for lock file ${lockPath} after ${timeoutMs}ms`,
  );
}
