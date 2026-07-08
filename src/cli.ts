import { parseScanArgs, CliUsageError } from './cli/args';
import { runScan } from './cli/scan-command';
import { DEFAULT_INCLUDE_EXTENSIONS } from './cli/discover-files';

const HELP = `agentarmor — scan files for AI agent traps

Usage:
  agentarmor scan <path...> [options]

Options:
  --strictness <permissive|balanced|strict>   Confidence threshold (default: balanced)
  --format <text|json|sarif>                  Output format (default: text)
  --fail-on <none|low|medium|high|critical>   Minimum risk level that fails the run (default: low)
  --ml                                        Use the ML classifier (requires @stylusnexus/agentarmor-ml)
  --include <.ext,.ext,...>                   Override default file extensions for directory scans
                                               (default: ${DEFAULT_INCLUDE_EXTENSIONS.join(', ')})
  --help, -h                                  Show this help

Exit codes:
  0   clean (no threat at or above --fail-on)
  1   threat(s) found at or above --fail-on
  2   usage error or I/O error

Examples:
  npx agentarmor scan CLAUDE.md
  npx agentarmor scan . --format sarif --fail-on high > results.sarif
  npx agentarmor scan docs/ --format json --ml
`;

/** Pure CLI runner — returns an exit code, never calls process.exit. */
export async function runCli(argv: string[]): Promise<number> {
  if (argv.length === 0 || argv.includes('--help') || argv.includes('-h')) {
    console.log(HELP);
    return argv.length === 0 ? 2 : 0;
  }

  const [command, ...rest] = argv;

  if (command !== 'scan') {
    console.error(`Unknown command: ${command}\n`);
    console.log(HELP);
    return 2;
  }

  try {
    const options = parseScanArgs(rest);
    const { output, exitCode } = await runScan(options);
    console.log(output);
    return exitCode;
  } catch (err) {
    if (err instanceof CliUsageError) {
      console.error(`Error: ${err.message}\n`);
      console.log(HELP);
      return 2;
    }
    const message = err instanceof Error ? err.message : String(err);
    console.error(`Unexpected error: ${message}`);
    return 2;
  }
}

/* c8 ignore start -- process.exit path, exercised manually in Task 7, not via vitest */
if (require.main === module) {
  runCli(process.argv.slice(2)).then((code) => process.exit(code));
}
/* c8 ignore stop */
