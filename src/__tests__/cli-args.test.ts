import { describe, it, expect } from 'vitest';
import { parseScanArgs, CliUsageError } from '../cli/args';

describe('parseScanArgs', () => {
  it('parses a single path with all defaults', () => {
    const opts = parseScanArgs(['file.md']);
    expect(opts).toEqual({
      paths: ['file.md'],
      strictness: 'balanced',
      format: 'text',
      failOn: 'low',
      ml: false,
      include: undefined,
    });
  });

  it('parses multiple paths', () => {
    const opts = parseScanArgs(['a.md', 'b.md', 'dir/']);
    expect(opts.paths).toEqual(['a.md', 'b.md', 'dir/']);
  });

  it('parses --strictness, --format, --fail-on, --ml together', () => {
    const opts = parseScanArgs([
      'file.md', '--strictness', 'strict', '--format', 'sarif', '--fail-on', 'high', '--ml',
    ]);
    expect(opts.strictness).toBe('strict');
    expect(opts.format).toBe('sarif');
    expect(opts.failOn).toBe('high');
    expect(opts.ml).toBe(true);
  });

  it('parses --include as a comma-separated list', () => {
    const opts = parseScanArgs(['dir/', '--include', '.yaml,.yml']);
    expect(opts.include).toEqual(['.yaml', '.yml']);
  });

  it('throws CliUsageError with no paths', () => {
    expect(() => parseScanArgs(['--format', 'json'])).toThrow(CliUsageError);
  });

  it('throws CliUsageError on an invalid --strictness value', () => {
    expect(() => parseScanArgs(['file.md', '--strictness', 'bogus'])).toThrow(CliUsageError);
  });

  it('throws CliUsageError on an invalid --format value', () => {
    expect(() => parseScanArgs(['file.md', '--format', 'xml'])).toThrow(CliUsageError);
  });

  it('throws CliUsageError on an invalid --fail-on value', () => {
    expect(() => parseScanArgs(['file.md', '--fail-on', 'extreme'])).toThrow(CliUsageError);
  });

  it('throws CliUsageError when a flag is missing its value', () => {
    expect(() => parseScanArgs(['file.md', '--strictness'])).toThrow(CliUsageError);
  });
});
