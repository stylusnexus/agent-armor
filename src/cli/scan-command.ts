import { readFileSync, statSync } from 'node:fs';
import { AgentArmor } from '../agent-armor';
import type { ScanCliOptions } from './args';
import { discoverFiles } from './discover-files';
import { formatText, formatJson, formatSarif, type FileScanResult } from './formatters';
import { meetsOrExceeds } from './severity';

export interface ScanCommandResult {
  output: string;
  error?: string;
  exitCode: 0 | 1 | 2;
}

export async function runScan(options: ScanCliOptions, stdinContent?: string): Promise<ScanCommandResult> {
  let files: string[];
  const missing: string[] = [];
  let paths: string[];
  try {
    paths = options.paths.filter((candidate) => candidate !== '-').filter((candidate) => {
      try {
        statSync(candidate);
        return true;
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
        missing.push(candidate);
        return options.strictMissing === true;
      }
    });
    if (options.strictMissing && missing.length > 0) {
      return { output: '', error: `Missing path(s): ${missing.join(', ')}`, exitCode: 2 };
    }
    files = discoverFiles(paths, options.include);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { output: '', error: `Error reading paths: ${message}`, exitCode: 2 };
  }

  if (missing.length > 0) {
    console.error(`Skipping missing path(s): ${missing.join(', ')}`);
  }
  const scanStdin = options.paths.includes('-');
  if (files.length === 0 && !scanStdin) {
    const message = missing.length > 0
      ? 'No files to scan: every specified path was missing.'
      : 'No files matched the given paths/include filters.';
    return { output: '', error: message, exitCode: 2 };
  }

  const armor = options.ml
    ? await AgentArmor.create({ strictness: options.strictness, ml: { enabled: true } })
    : AgentArmor.regexOnly({ strictness: options.strictness });

  if (options.ml && !armor.mlActive) {
    if (options.requireMl) {
      return {
        output: '',
        error: 'Error: --require-ml was given but the ML classifier could not be loaded.',
        exitCode: 2,
      };
    }
    console.error(
      'WARNING: --ml was requested but the ML classifier is unavailable. ' +
        'Scanning with regex detectors only. Use --require-ml to fail instead.',
    );
  }

  const results: FileScanResult[] = [];
  const inputs: Array<{ file: string; content: string }> = [];
  if (scanStdin) {
    inputs.push({ file: '-', content: stdinContent ?? (await readStdin()) });
  }
  for (const file of files) {
    let content: string;
    try {
      content = readFileSync(file, 'utf8');
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return { output: '', error: `Error reading ${file}: ${message}`, exitCode: 2 };
    }
    inputs.push({ file, content });
  }
  for (const { file, content } of inputs) {
    const result = options.ml ? await armor.scan(content) : armor.scanSync(content);
    results.push({ file, content, result });
  }

  const output =
    options.format === 'json'
      ? formatJson(results)
      : options.format === 'sarif'
        ? formatSarif(results)
        : formatText(results);

  // A degraded scan (a detector threw) has no threat to rank, so it fails on its own.
  const anyFailure =
    options.failOn !== 'none' &&
    results.some(
      ({ result }) =>
        meetsOrExceeds(result.riskLevel, options.failOn) || result.stats.degraded === true,
    );

  return { output, exitCode: anyFailure ? 1 : 0 };
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks).toString('utf8');
}
