import path from 'node:path';
import type { ScanResult, Threat } from '../types';
import { severityToSarifLevel } from './severity';

export interface FileScanResult {
  file: string;
  result: ScanResult;
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
    lines.push(`[BLOCKED] ${file} - ${result.threats.length} threat(s), risk: ${result.riskLevel}:`);
    for (const threat of result.threats) {
      lines.push(
        `    [${threat.severity.toUpperCase()}] ${threat.type} (${threat.detectorId}) ` +
          `${(threat.confidence * 100).toFixed(0)}% - "${threat.evidence.slice(0, 70)}"`
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

export function formatSarif(results: FileScanResult[]): string {
  const ruleIds = new Set<string>();
  const sarifResults: unknown[] = [];

  for (const { file, result } of results) {
    for (const threat of result.threats as Threat[]) {
      ruleIds.add(threat.detectorId);
      const location = threat.location
        ? [
            {
              physicalLocation: {
                artifactLocation: { uri: toFileUri(file) },
                region: {
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

  const sarif = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
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
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}

/** Forward-slash path for SARIF artifactLocation.uri (SARIF requires URI-style separators). */
function toFileUri(filePath: string): string {
  return filePath.split(path.sep).join('/');
}
