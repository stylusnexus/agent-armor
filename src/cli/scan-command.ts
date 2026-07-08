import { readFileSync } from 'node:fs';
import { AgentArmor } from '../agent-armor';
import type { ScanCliOptions } from './args';
import { discoverFiles } from './discover-files';
import { formatText, formatJson, formatSarif, type FileScanResult } from './formatters';
import { meetsOrExceeds } from './severity';

export interface ScanCommandResult {
  output: string;
  exitCode: 0 | 1 | 2;
}

export async function runScan(options: ScanCliOptions): Promise<ScanCommandResult> {
  let files: string[];
  try {
    files = discoverFiles(options.paths, options.include);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { output: `Error reading paths: ${message}`, exitCode: 2 };
  }

  if (files.length === 0) {
    return { output: 'No files matched the given paths/include filters.', exitCode: 2 };
  }

  const armor = options.ml
    ? await AgentArmor.create({ strictness: options.strictness, ml: { enabled: true } })
    : AgentArmor.regexOnly({ strictness: options.strictness });

  const results: FileScanResult[] = [];
  for (const file of files) {
    let content: string;
    try {
      content = readFileSync(file, 'utf8');
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return { output: `Error reading ${file}: ${message}`, exitCode: 2 };
    }
    const result = options.ml ? await armor.scan(content) : armor.scanSync(content);
    results.push({ file, result });
  }

  const output =
    options.format === 'json'
      ? formatJson(results)
      : options.format === 'sarif'
        ? formatSarif(results)
        : formatText(results);

  const anyFailure = results.some(({ result }) => meetsOrExceeds(result.riskLevel, options.failOn));

  return { output, exitCode: anyFailure ? 1 : 0 };
}
