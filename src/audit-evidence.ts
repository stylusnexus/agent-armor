import { createHash } from 'node:crypto';
import type { AuditRecord, EvidencePackage } from './types';

/** sha256 over the records in their given order — matches AuditThreatSummary.evidenceHash's format. */
function digestRecords(records: AuditRecord[]): string {
  const canonical = records.map((r) => JSON.stringify(r)).join('\n');
  return `sha256:${createHash('sha256').update(canonical).digest('hex')}`;
}

function countDecisions(records: AuditRecord[]): EvidencePackage['decisionCounts'] {
  const counts: EvidencePackage['decisionCounts'] = {
    allow: 0,
    sanitize: 0,
    block: 0,
    exception: 0,
  };
  for (const r of records) counts[r.decision]++;
  return counts;
}

function collectDetectorVersions(records: AuditRecord[]): string[] {
  const versions = new Set<string>();
  for (const r of records) {
    versions.add(`patterns@${r.patternDbVersion}`);
    if (r.mlModelVersion) versions.add(`ml@${r.mlModelVersion}`);
  }
  return [...versions].sort();
}

/**
 * Aggregates a set of {@link AuditRecord}s (e.g. read from a JSONL sink) into a
 * single tamper-evident {@link EvidencePackage} for a reporting period.
 * `records` must be in their original append order — the digest is order-sensitive.
 */
export function buildEvidencePackage(
  records: AuditRecord[],
  period: { periodStart: string; periodEnd: string }
): EvidencePackage {
  return {
    schemaVersion: 'audit-evidence-package.v1',
    periodStart: period.periodStart,
    periodEnd: period.periodEnd,
    recordCount: records.length,
    decisionCounts: countDecisions(records),
    detectorVersions: collectDetectorVersions(records),
    exceptionRecordIds: records.filter((r) => r.decision === 'exception').map((r) => r.scanId),
    rawContentStored: records.some((r) => r.threats.some((t) => t.evidence !== undefined)),
    packageDigest: digestRecords(records),
  };
}

/**
 * Re-derives an {@link EvidencePackage} from `records` and checks it against `pkg`.
 * Returns false if the record set has been altered in any way since the package
 * was built — a single edited/added/removed/reordered record changes the digest.
 */
export function verifyEvidencePackage(records: AuditRecord[], pkg: EvidencePackage): boolean {
  const rebuilt = buildEvidencePackage(records, {
    periodStart: pkg.periodStart,
    periodEnd: pkg.periodEnd,
  });
  return (
    rebuilt.packageDigest === pkg.packageDigest &&
    rebuilt.recordCount === pkg.recordCount &&
    JSON.stringify(rebuilt.decisionCounts) === JSON.stringify(pkg.decisionCounts)
  );
}
