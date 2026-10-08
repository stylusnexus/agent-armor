import { AgentArmor } from '../../agent-armor';
import type { AgentArmorConfig, Strictness } from '../../types';

/** The detectors a test can run alone, keyed by detector id. */
const SOLO_FLAGS = {
  'hidden-html': ['contentInjection', 'hiddenHTML'],
  'metadata-injection': ['contentInjection', 'metadataInjection'],
  'dynamic-cloaking': ['contentInjection', 'dynamicCloaking'],
  'syntactic-masking': ['contentInjection', 'syntacticMasking'],
  'jailbreak-patterns': ['behaviouralControl', 'jailbreakPatterns'],
  exfiltration: ['behaviouralControl', 'exfiltrationURLs'],
  'sub-agent-spawning': ['behaviouralControl', 'privilegeEscalation'],
  'rag-knowledge-poisoning': ['cognitiveState', 'ragPoisoning'],
  'latent-memory-poisoning': ['cognitiveState', 'memoryPoisoning'],
  'contextual-learning-trap': ['cognitiveState', 'contextualLearning'],
  'biased-framing': ['semanticManipulation', 'biasedFraming'],
  'oversight-evasion': ['semanticManipulation', 'oversightEvasion'],
  'persona-hyperstition': ['semanticManipulation', 'personaHyperstition'],
  'dependency-substitution': ['transportIntegrity', 'dependencySubstitution'],
} as const;

export type SoloDetectorId = keyof typeof SOLO_FLAGS;

const GROUPS = {
  contentInjection: [
    'hiddenHTML',
    'metadataInjection',
    'dynamicCloaking',
    'syntacticMasking',
    'steganographicPayload',
  ],
  behaviouralControl: ['jailbreakPatterns', 'exfiltrationURLs', 'privilegeEscalation'],
  cognitiveState: ['ragPoisoning', 'memoryPoisoning', 'contextualLearning'],
  semanticManipulation: ['biasedFraming', 'oversightEvasion', 'personaHyperstition'],
  transportIntegrity: [
    'toolCallTampering',
    'credentialExposure',
    'dependencySubstitution',
    'responseAnomaly',
  ],
} as const;

/**
 * An armor with every shipped detector off except `id`, so a test exercises
 * that detector's patterns and nothing else.
 */
export function soloDetector(id: SoloDetectorId, strictness: Strictness = 'balanced'): AgentArmor {
  const [group, flag] = SOLO_FLAGS[id];
  const config: Record<string, Record<string, boolean>> = {};
  for (const [g, flags] of Object.entries(GROUPS)) {
    config[g] = Object.fromEntries(flags.map((f) => [f, g === group && f === flag]));
  }
  return AgentArmor.regexOnly({ strictness, ...config } as AgentArmorConfig);
}

/** An armor with every shipped detector on except `id`. */
export function withoutDetector(
  id: SoloDetectorId,
  strictness: Strictness = 'balanced',
): AgentArmor {
  const [group, flag] = SOLO_FLAGS[id];
  return AgentArmor.regexOnly({ strictness, [group]: { [flag]: false } } as AgentArmorConfig);
}
