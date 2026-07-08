import { describe, it, expect, vi, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { runCli } from '../cli';

describe('runCli', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('prints help and exits 2 with zero arguments', async () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const code = await runCli([]);
    expect(code).toBe(2);
    expect(logSpy).toHaveBeenCalledWith(expect.stringContaining('Usage:'));
  });

  it('prints help and exits 0 with --help', async () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const code = await runCli(['--help']);
    expect(code).toBe(0);
    expect(logSpy).toHaveBeenCalledWith(expect.stringContaining('Usage:'));
  });

  it('exits 2 on an unknown command', async () => {
    vi.spyOn(console, 'log').mockImplementation(() => {});
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const code = await runCli(['bogus-command']);
    expect(code).toBe(2);
    expect(errSpy).toHaveBeenCalledWith(expect.stringContaining('Unknown command'));
  });

  it('exits 2 on a scan usage error (no paths)', async () => {
    vi.spyOn(console, 'log').mockImplementation(() => {});
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const code = await runCli(['scan']);
    expect(code).toBe(2);
    expect(errSpy).toHaveBeenCalledWith(expect.stringContaining('Error:'));
  });

  it('scans a real clean file end-to-end and exits 0', async () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'agentarmor-entry-test-'));
    const file = path.join(dir, 'clean.md');
    writeFileSync(file, 'Nothing suspicious here.');
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const code = await runCli(['scan', file]);
    expect(code).toBe(0);
    expect(logSpy).toHaveBeenCalledWith(expect.stringContaining('[ok]'));
    rmSync(dir, { recursive: true, force: true });
  });
});
