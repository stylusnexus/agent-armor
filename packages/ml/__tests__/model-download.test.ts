import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdtemp, readFile, rm } from 'fs/promises';
import { PassThrough } from 'stream';
import { join } from 'path';
import { tmpdir } from 'os';

// The pinned Hugging Face revision answers a download with a redirect whose
// Location is a relative path (/api/resolve-cache/...). The first release that
// pinned the revision (0.1.6) passed that path straight to https.get and failed
// with ERR_INVALID_URL, so no model ever downloaded. This replays that exchange.

const requested: string[] = [];

vi.mock('https', () => ({
  get: (url: string, cb: (res: unknown) => void) => {
    requested.push(String(url));
    const req = new PassThrough();
    queueMicrotask(() => {
      if (requested.length === 1) {
        const res = new PassThrough() as PassThrough & {
          statusCode: number;
          headers: Record<string, string>;
        };
        res.statusCode = 302;
        res.headers = { location: '/api/resolve-cache/models/org/repo/abc/file.bin?etag=%22x%22' };
        cb(res);
        res.end();
      } else {
        const res = new PassThrough() as PassThrough & {
          statusCode: number;
          headers: Record<string, string>;
        };
        res.statusCode = 200;
        res.headers = { 'content-length': '5' };
        cb(res);
        res.end('hello');
      }
    });
    return req;
  },
}));

describe('downloadFile redirects', () => {
  let dir: string;
  beforeEach(async () => {
    requested.length = 0;
    dir = await mkdtemp(join(tmpdir(), 'agentarmor-dl-test-'));
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it('follows a relative Location against the URL that redirected', async () => {
    const { downloadFile } = await import('../src/model-manager');
    await downloadFile(
      'file.bin',
      dir,
      { modelUrl: 'https://huggingface.co/org/repo/resolve/v2' },
      false,
    );

    expect(requested).toEqual([
      'https://huggingface.co/org/repo/resolve/v2/file.bin',
      'https://huggingface.co/api/resolve-cache/models/org/repo/abc/file.bin?etag=%22x%22',
    ]);
    expect(await readFile(join(dir, 'file.bin'), 'utf-8')).toBe('hello');
  });
});
