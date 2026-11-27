import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { symlinkSync } from 'fs';
import { access, lstat, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'fs/promises';
import { PassThrough } from 'stream';
import { join } from 'path';
import { tmpdir } from 'os';

type Response = PassThrough & { statusCode: number; headers: Record<string, string> };

// Each test sets how the fake server answers a request.
let respond: (cb: (res: Response) => void) => void;
const requests: { url: string; req: PassThrough }[] = [];

vi.mock('https', () => ({
  get: (url: string, cb: (res: Response) => void) => {
    // Node's https.get throws synchronously for any other protocol.
    if (!url.startsWith('https:')) throw new TypeError(`Protocol not supported: ${url}`);
    const req = new PassThrough();
    requests.push({ url, req });
    queueMicrotask(() => respond(cb));
    return req;
  },
}));

function response(statusCode: number, headers: Record<string, string> = {}): Response {
  return Object.assign(new PassThrough(), { statusCode, headers });
}

function serve(body: string) {
  return (cb: (res: Response) => void) => {
    const res = response(200);
    cb(res);
    res.end(body);
  };
}

const config = { modelUrl: 'https://models.example/m', download: { retries: 0 } };

let dir: string;
beforeEach(async () => {
  requests.length = 0;
  dir = await mkdtemp(join(tmpdir(), 'agentarmor-hardening-'));
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

const exists = (path: string) =>
  access(path).then(
    () => true,
    () => false,
  );

describe('downloadFile redirect targets', () => {
  it.each([
    ['an http address', 'http://models.example/m/file.bin'],
    ['a malformed address', 'https://[not-a-host'],
  ])('fails with DOWNLOAD_FAILED on a redirect to %s', async (_name, location) => {
    const { downloadFile } = await import('../src/model-manager');
    respond = (cb) => cb(response(302, { location }));

    await expect(downloadFile('file.bin', dir, config, false)).rejects.toMatchObject({
      code: 'DOWNLOAD_FAILED',
    });
    expect(requests).toHaveLength(1);
  });
});

describe('downloadFile model address', () => {
  it.each([
    ['an http address', 'http://models.example/m'],
    ['a malformed address', 'not-a-url'],
  ])('fails with DOWNLOAD_FAILED and leaves no timer for %s', async (_name, modelUrl) => {
    const { downloadFile } = await import('../src/model-manager');
    vi.useFakeTimers();
    try {
      await expect(
        downloadFile('file.bin', dir, { ...config, modelUrl }, false),
      ).rejects.toMatchObject({ code: 'DOWNLOAD_FAILED' });
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('downloadFile timeout', () => {
  it('destroys the request so the transfer stops', async () => {
    const { downloadFile } = await import('../src/model-manager');
    respond = (cb) => cb(response(200)); // never ends

    await expect(
      downloadFile('file.bin', dir, { ...config, download: { retries: 0, timeoutMs: 50 } }, false),
    ).rejects.toMatchObject({ code: 'DOWNLOAD_TIMEOUT' });
    expect(requests[0].req.destroyed).toBe(true);
  });
});

describe('downloadFile temp file', () => {
  it('does not write through a symlink left at the temp path', async () => {
    const { downloadFile } = await import('../src/model-manager');
    const victim = join(dir, 'victim');
    await writeFile(victim, 'untouched');
    await symlink(victim, join(dir, 'file.bin.tmp'));
    respond = serve('downloaded');

    await downloadFile('file.bin', dir, config, false);

    expect(await readFile(victim, 'utf-8')).toBe('untouched');
    expect((await lstat(join(dir, 'file.bin'))).isSymbolicLink()).toBe(false);
    expect(await readFile(join(dir, 'file.bin'), 'utf-8')).toBe('downloaded');
  });

  it('fails if a symlink appears at the temp path during the request', async () => {
    const { downloadFile } = await import('../src/model-manager');
    const victim = join(dir, 'victim');
    await writeFile(victim, 'untouched');
    respond = (cb) => {
      symlinkSync(victim, join(dir, 'file.bin.tmp'));
      serve('downloaded')(cb);
    };

    await expect(downloadFile('file.bin', dir, config, false)).rejects.toMatchObject({
      code: 'DOWNLOAD_FAILED',
    });
    expect(await readFile(victim, 'utf-8')).toBe('untouched');
  });
});

describe('clearCache', () => {
  const owned = [
    'model_quantized.onnx',
    'model_quantized.onnx.tmp',
    'tokenizer.json',
    'label_map.json',
    'tokenizer_config.json',
    'special_tokens_map.json',
    'model.onnx.lock',
  ];
  const key = 'a'.repeat(64);

  it('removes its own files and the folder when nothing else is in it', async () => {
    const { clearCache } = await import('../src/model-manager');
    const cache = join(dir, 'cache');
    await mkdir(join(cache, 'custom', key), { recursive: true });
    for (const file of owned) {
      await writeFile(join(cache, file), 'x');
      await writeFile(join(cache, 'custom', key, file), 'x');
    }

    await clearCache(cache);

    expect(await exists(cache)).toBe(false);
  });

  it('keeps files and folders it did not create', async () => {
    const { clearCache } = await import('../src/model-manager');
    await mkdir(join(dir, 'other-app'));
    await mkdir(join(dir, 'custom', 'mine'), { recursive: true });
    const kept = [
      join(dir, 'notes.txt'),
      join(dir, 'other-app', 'tokenizer.json'),
      join(dir, 'custom', 'mine', 'tokenizer.json'),
    ];
    for (const path of kept) await writeFile(path, 'keep');
    await writeFile(join(dir, 'tokenizer.json'), 'x');

    await clearCache(dir);

    for (const path of kept) expect(await readFile(path, 'utf-8')).toBe('keep');
    expect(await exists(join(dir, 'tokenizer.json'))).toBe(false);
  });

  it('does not follow a symlinked custom folder', async () => {
    const { clearCache } = await import('../src/model-manager');
    const outside = join(dir, 'outside');
    await mkdir(join(outside, key), { recursive: true });
    await writeFile(join(outside, key, 'tokenizer.json'), 'keep');
    const cache = join(dir, 'cache');
    await mkdir(cache);
    await symlink(outside, join(cache, 'custom'));

    await clearCache(cache);

    expect(await readFile(join(outside, key, 'tokenizer.json'), 'utf-8')).toBe('keep');
  });

  it('succeeds when the cache folder is a symlink', async () => {
    const { clearCache } = await import('../src/model-manager');
    const real = join(dir, 'real');
    await mkdir(real);
    await writeFile(join(real, 'tokenizer.json'), 'x');
    const link = join(dir, 'link');
    await symlink(real, link);

    await expect(clearCache(link)).resolves.toBeUndefined();
    expect(await exists(join(real, 'tokenizer.json'))).toBe(false);
  });

  it('removes the other files and then reports one it cannot delete', async () => {
    const { clearCache } = await import('../src/model-manager');
    // A folder at a file name makes unlink fail.
    await mkdir(join(dir, 'model_quantized.onnx'));
    await writeFile(join(dir, 'label_map.json'), 'x');

    await expect(clearCache(dir)).rejects.toThrow('model_quantized.onnx');
    expect(await exists(join(dir, 'label_map.json'))).toBe(false);
  });

  it('succeeds when the cache folder does not exist', async () => {
    const { clearCache } = await import('../src/model-manager');
    await expect(clearCache(join(dir, 'missing'))).resolves.toBeUndefined();
  });
});
