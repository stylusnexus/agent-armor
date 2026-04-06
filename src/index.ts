export { AgentArmor } from './agent-armor';

// Pattern database (for custom patterns / remote updates)
export type { PatternDatabase, PatternEntry } from './patterns';
export { DEFAULT_PATTERNS } from './patterns';

// Detectors (for advanced usage / custom pipelines)
export { PatternDetector } from './detectors/pattern-detector';
export { BaseDetector } from './detectors';
export type { PatternMatch } from './detectors';

// Legacy individual detectors (still available for direct use)
export {
  HiddenHTMLDetector,
  MetadataInjectionDetector,
  DynamicCloakingDetector,
  SyntacticMaskingDetector,
  JailbreakPatternDetector,
  ExfiltrationDetector,
  SubAgentSpawningDetector,
} from './detectors';

export type {
  AgentArmorConfig,
  Confidence,
  Detector,
  DetectorOptions,
  DetectorResult,
  ScanResult,
  Severity,
  Strictness,
  Threat,
  TrapCategory,
  TrapType,
  ContentInjectionType,
  SemanticManipulationType,
  CognitiveStateType,
  BehaviouralControlType,
  SystemicType,
  HumanInTheLoopType,
} from './types';
