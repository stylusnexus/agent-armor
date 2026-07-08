import type { RiskLevel, Strictness } from '../types';

const STRICTNESS_VALUES: Strictness[] = ['permissive', 'balanced', 'strict'];
const FORMAT_VALUES = ['text', 'json', 'sarif'] as const;
const RISK_LEVEL_VALUES: RiskLevel[] = ['none', 'low', 'medium', 'high', 'critical'];

export type OutputFormat = (typeof FORMAT_VALUES)[number];

export interface ScanCliOptions {
  paths: string[];
  strictness: Strictness;
  format: OutputFormat;
  failOn: RiskLevel;
  ml: boolean;
  include?: string[];
}

/** Thrown for any invalid CLI invocation — callers map this to exit code 2. */
export class CliUsageError extends Error {}

function readFlagValue(argv: string[], flag: string): string | undefined {
  const i = argv.indexOf(flag);
  if (i === -1) return undefined;
  const value = argv[i + 1];
  if (value === undefined || value.startsWith('--')) {
    throw new CliUsageError(`${flag} requires a value`);
  }
  return value;
}

/** Parses `scan <path...> [--strictness] [--format] [--fail-on] [--ml] [--include]`. */
export function parseScanArgs(argv: string[]): ScanCliOptions {
  const strictnessRaw = readFlagValue(argv, '--strictness');
  const formatRaw = readFlagValue(argv, '--format');
  const failOnRaw = readFlagValue(argv, '--fail-on');
  const includeRaw = readFlagValue(argv, '--include');
  const ml = argv.includes('--ml');

  const strictness = (strictnessRaw ?? 'balanced') as Strictness;
  if (!STRICTNESS_VALUES.includes(strictness)) {
    throw new CliUsageError(
      `Invalid --strictness "${strictnessRaw}" — expected one of: ${STRICTNESS_VALUES.join(', ')}`
    );
  }

  const format = (formatRaw ?? 'text') as OutputFormat;
  if (!FORMAT_VALUES.includes(format)) {
    throw new CliUsageError(
      `Invalid --format "${formatRaw}" — expected one of: ${FORMAT_VALUES.join(', ')}`
    );
  }

  const failOn = (failOnRaw ?? 'low') as RiskLevel;
  if (!RISK_LEVEL_VALUES.includes(failOn)) {
    throw new CliUsageError(
      `Invalid --fail-on "${failOnRaw}" — expected one of: ${RISK_LEVEL_VALUES.join(', ')}`
    );
  }

  const flagsAndValues = new Set([
    '--strictness', strictnessRaw,
    '--format', formatRaw,
    '--fail-on', failOnRaw,
    '--include', includeRaw,
    '--ml',
  ]);
  const paths = argv.filter((a) => !flagsAndValues.has(a));

  if (paths.length === 0) {
    throw new CliUsageError('No paths given. Usage: agentarmor scan <path...> [options]');
  }

  return {
    paths,
    strictness,
    format,
    failOn,
    ml,
    include: includeRaw ? includeRaw.split(',') : undefined,
  };
}
