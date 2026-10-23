import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdir, mkdtemp, readdir, rm, writeFile } from 'fs/promises';
import { PassThrough } from 'stream';
import { join } from 'path';
import { tmpdir } from 'os';

// #359: a bad `modelChecksums` used to be caught as a cache miss, so every
// start downloaded the ~165MB model, failed the same check, and deleted it.
// The download is mocked here so a test can assert it never starts.

const requested: string[] = [];

vi.mock('https', () => ({
  get: (url: string, cb: (res: unknown) => void) => {
    requested.push(String(url));
    const req = new PassThrough();
    queueMicrotask(() => {
      const res = new PassThrough() as PassThrough & {
        statusCode: number;
        headers: Record<string, string>;
      };
      res.statusCode = 404;
      res.headers = {};
      cb(res);
      res.end();
    });
    return req;
  },
}));

const VALID = 'a'.repeat(64);
const FULL = {
  'model_quantized.onnx': VALID,
  'tokenizer.json': VALID,
  'label_map.json': VALID,
};

describe('resolveModel with a bad modelChecksums', () => {
  let cacheRoot: string;
  const env = { ...process.env };

  beforeEach(async () => {
    requested.length = 0;
    cacheRoot = await mkdtemp(join(tmpdir(), 'agentarmor-checksum-config-'));
    process.env.AGENTARMOR_CACHE_DIR = cacheRoot;
    delete process.env.AGENTARMOR_MODEL_DIR;
  });

  afterEach(async () => {
    process.env = { ...env };
    await rm(cacheRoot, { recursive: true, force: true });
  });

  const bad: Array<[string, Record<string, string>]> = [
    ['a missing entry', { 'model_quantized.onnx': VALID, 'tokenizer.json': VALID }],
    ['a truncated digest', { ...FULL, 'label_map.json': VALID.slice(1) }],
    ['a non-hex digest', { ...FULL, 'tokenizer.json': 'z'.repeat(64) }],
  ];

  it.each(bad)('fails CHECKSUM_REQUIRED on %s without downloading', async (_name, checksums) => {
    const { resolveModel } = await import('../src/model-manager');
    await expect(
      resolveModel({ modelChecksums: checksums as never, download: { retries: 0 } }),
    ).rejects.toMatchObject({ code: 'CHECKSUM_REQUIRED' });
    expect(requested).toEqual([]);
    // Fails before touching the cache at all.
    expect(await readdir(cacheRoot)).toEqual([]);
  });

  it('fails CHECKSUM_REQUIRED for a modelDir before checking its files', async () => {
    const { resolveModel } = await import('../src/model-manager');
    await expect(
      resolveModel({
        modelDir: join(cacheRoot, 'does-not-exist'),
        modelChecksums: { 'model_quantized.onnx': VALID } as never,
      }),
    ).rejects.toMatchObject({ code: 'CHECKSUM_REQUIRED' });
  });
});

describe('resolveModel cache check', () => {
  let cacheRoot: string;
  const env = { ...process.env };

  beforeEach(async () => {
    requested.length = 0;
    cacheRoot = await mkdtemp(join(tmpdir(), 'agentarmor-cache-check-'));
    process.env.AGENTARMOR_CACHE_DIR = cacheRoot;
    delete process.env.AGENTARMOR_MODEL_DIR;
  });

  afterEach(async () => {
    process.env = { ...env };
    await rm(cacheRoot, { recursive: true, force: true });
  });

  it('still downloads when the cache is empty', async () => {
    const { resolveModel } = await import('../src/model-manager');
    await expect(resolveModel({ download: { retries: 0 } })).rejects.toMatchObject({
      code: 'DOWNLOAD_FAILED',
    });
    expect(requested.length).toBeGreaterThan(0);
  });

  it('rethrows an unreadable cache file instead of downloading over it', async () => {
    const { resolveModel } = await import('../src/model-manager');
    // Every required name exists, but the model "file" is a directory, so
    // hashing it fails with EISDIR: not a miss a download could fix.
    await mkdir(join(cacheRoot, 'model_quantized.onnx'));
    await writeFile(join(cacheRoot, 'tokenizer.json'), '{}');
    await writeFile(join(cacheRoot, 'label_map.json'), '{}');

    await expect(resolveModel({ download: { retries: 0 } })).rejects.toMatchObject({
      code: 'EISDIR',
    });
    expect(requested).toEqual([]);
  });
});
