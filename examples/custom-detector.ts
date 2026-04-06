/**
 * Example: Building a custom detector
 *
 * Extend Agent Armor with domain-specific detection logic.
 * Your detector plugs into the same pipeline as the built-in ones.
 */
import { AgentArmor, type Detector, type DetectorResult, type DetectorOptions } from '@stylusnexus/agentarmor';

/**
 * Custom detector that flags content mentioning specific
 * internal project names that should never appear in external content.
 */
const internalNameDetector: Detector = {
  id: 'internal-name-leak',
  name: 'Internal Name Leak Detector',
  category: 'behavioural-control',

  scan(content: string, options?: DetectorOptions): DetectorResult {
    const internalNames = ['Project Chimera', 'Operation Midnight', 'VAULT-7'];
    const threats = [];

    for (const name of internalNames) {
      const index = content.indexOf(name);
      if (index !== -1) {
        threats.push({
          category: 'behavioural-control' as const,
          type: 'data-exfiltration' as const,
          severity: 'critical' as const,
          confidence: 1.0,
          description: `Internal project name "${name}" detected in external content`,
          evidence: content.slice(Math.max(0, index - 20), index + name.length + 20),
          location: { offset: index, length: name.length },
          detectorId: 'internal-name-leak',
          source: 'custom' as const,
        });
      }
    }

    return { threats };
  },

  sanitize(content: string, threats): string {
    let result = content;
    // Replace in reverse order to preserve offsets
    const sorted = [...threats].sort((a, b) =>
      (b.location?.offset ?? 0) - (a.location?.offset ?? 0)
    );
    for (const threat of sorted) {
      if (threat.location) {
        result = result.slice(0, threat.location.offset)
          + '[REDACTED]'
          + result.slice(threat.location.offset + threat.location.length);
      }
    }
    return result;
  },
};

// Use it
const armor = AgentArmor.regexOnly({
  strictness: 'balanced',
  customDetectors: [internalNameDetector],
});

const content = 'The latest update to Project Chimera shows promising results in the Q3 report.';
const result = armor.scanSync(content);

console.log('Custom Detector Demo:');
console.log('  Clean:', result.clean);
if (!result.clean) {
  for (const t of result.threats) {
    console.log(`  [${t.source}] ${t.description}`);
  }
  console.log('  Sanitized:', result.sanitized);
}
