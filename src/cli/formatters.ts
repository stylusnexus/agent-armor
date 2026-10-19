import path from 'node:path';
import type { ScanResult, Threat } from '../types';
import { severityToSarifLevel } from './severity';

export interface FileScanResult {
  file: string;
  result: ScanResult;
  content?: string;
}

export function formatText(results: FileScanResult[]): string {
  const lines: string[] = [];
  let blocked = 0;

  for (const { file, result } of results) {
    if (result.clean) {
      lines.push(`[ok]      ${file} - clean (${result.durationMs.toFixed(2)} ms)`);
      continue;
    }
    blocked++;
    const degraded = result.stats.degraded
      ? ` DEGRADED, detector(s) failed: ${(result.stats.failedDetectors ?? []).join(', ')},`
      : '';
    lines.push(
      `[BLOCKED] ${file} - ${result.threats.length} threat(s),${degraded} risk: ${result.riskLevel}:`,
    );
    for (const threat of result.threats) {
      lines.push(
        `    [${threat.severity.toUpperCase()}] ${threat.type} (${threat.detectorId}) ` +
          `${(threat.confidence * 100).toFixed(0)}% - "${threat.evidence.slice(0, 70)}"`,
      );
    }
  }

  lines.push('-'.repeat(60));
  lines.push(`Scanned: ${results.length}  Blocked: ${blocked}  Clean: ${results.length - blocked}`);
  return lines.join('\n');
}

export function formatJson(results: FileScanResult[]): string {
  return JSON.stringify(results, null, 2);
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
}

function titleCase(id: string): string {
  return id
    .split(/[-_]/)
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(' ');
}

export function formatSarif(results: FileScanResult[], repositoryRoot = process.cwd()): string {
  const ruleIds = new Set<string>();
  const sarifResults: unknown[] = [];

  for (const { file, result } of results) {
    for (const threat of result.threats as Threat[]) {
      ruleIds.add(threat.detectorId);
      const location = threat.location
        ? [
            {
              physicalLocation: {
                artifactLocation: { uri: toFileUri(file, repositoryRoot) },
                region: {
                  startLine: lineAt(contentFor(results, file), threat.location.offset),
                  charOffset: threat.location.offset,
                  charLength: threat.location.length,
                },
              },
            },
          ]
        : undefined;

      sarifResults.push({
        ruleId: threat.detectorId,
        level: severityToSarifLevel(threat.severity),
        message: { text: threat.description },
        ...(location ? { locations: location } : {}),
      });
    }
  }

  const rules: SarifRule[] = [...ruleIds].sort().map((id) => ({
    id,
    name: titleCase(id),
    shortDescription: { text: `Agent Armor detector: ${titleCase(id)}` },
  }));

  const degraded = results.filter(({ result }) => result.stats.degraded);
  const sarif = {
    $schema:
      'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'agentarmor',
            informationUri: 'https://agentarmor.dev',
            rules,
          },
        },
        results: sarifResults,
        // Code scanning shows a run with no results as passing; say why it was not.
        ...(degraded.length > 0
          ? {
              invocations: [
                {
                  executionSuccessful: false,
                  toolExecutionNotifications: degraded.map(({ file, result }) => ({
                    level: 'error',
                    message: {
                      text: `Degraded scan: detector(s) ${(result.stats.failedDetectors ?? []).join(', ')} failed, so ${file} was not fully checked.`,
                    },
                    locations: [
                      { physicalLocation: { artifactLocation: { uri: toFileUri(file, repositoryRoot) } } },
                    ],
                  })),
                },
              ],
            }
          : {}),
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}

/** Forward-slash path for SARIF artifactLocation.uri (SARIF requires URI-style separators). */
function contentFor(results: FileScanResult[], file: string): string {
  return results.find((entry) => entry.file === file)?.content ?? '';
}

function lineAt(content: string, offset: number): number {
  let line = 1;
  for (let i = 0; i < Math.min(offset, content.length); i++) {
    if (content.charCodeAt(i) === 10) line++;
  }
  return line;
}

function toFileUri(filePath: string, repositoryRoot: string): string {
  const relative = path.relative(repositoryRoot, filePath) || path.basename(filePath);
  return relative.split(path.sep).join('/');
}
