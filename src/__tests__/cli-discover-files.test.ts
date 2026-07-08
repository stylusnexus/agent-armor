import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { discoverFiles, DEFAULT_INCLUDE_EXTENSIONS } from '../cli/discover-files';

describe('discoverFiles', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(path.join(tmpdir(), 'agentarmor-cli-test-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('always includes an explicitly-named file regardless of extension', () => {
    const file = path.join(dir, 'weird.ext');
    writeFileSync(file, 'content');
    const result = discoverFiles([file]);
    expect(result).toEqual([path.resolve(file)]);
  });

  it('recurses a directory and filters by default include extensions', () => {
    writeFileSync(path.join(dir, 'a.md'), 'x');
    writeFileSync(path.join(dir, 'b.png'), 'x');
    mkdirSync(path.join(dir, 'sub'));
    writeFileSync(path.join(dir, 'sub', 'c.txt'), 'x');
    const result = discoverFiles([dir]).sort();
    expect(result).toEqual(
      [path.resolve(dir, 'a.md'), path.resolve(dir, 'sub', 'c.txt')].sort()
    );
  });

  it('skips node_modules, .git, dist, coverage when recursing', () => {
    mkdirSync(path.join(dir, 'node_modules'));
    writeFileSync(path.join(dir, 'node_modules', 'skip.md'), 'x');
    writeFileSync(path.join(dir, 'keep.md'), 'x');
    const result = discoverFiles([dir]);
    expect(result).toEqual([path.resolve(dir, 'keep.md')]);
  });

  it('respects a custom include list, replacing the default', () => {
    writeFileSync(path.join(dir, 'a.md'), 'x');
    writeFileSync(path.join(dir, 'b.yaml'), 'x');
    const result = discoverFiles([dir], ['.yaml']);
    expect(result).toEqual([path.resolve(dir, 'b.yaml')]);
  });

  it('matches a dotfile include pattern like .cursorrules by exact name', () => {
    writeFileSync(path.join(dir, '.cursorrules'), 'x');
    const result = discoverFiles([dir]);
    expect(result).toEqual([path.resolve(dir, '.cursorrules')]);
  });

  it('exports the default include list for reuse by the CLI help text', () => {
    expect(DEFAULT_INCLUDE_EXTENSIONS).toContain('.md');
    expect(DEFAULT_INCLUDE_EXTENSIONS).toContain('.cursorrules');
  });
});
