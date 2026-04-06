export { AgentArmor } from './agent-armor';

// All detectors (for advanced usage / custom pipelines)
export {
  HiddenHTMLDetector,
  MetadataInjectionDetector,
  DynamicCloakingDetector,
  SyntacticMaskingDetector,
  JailbreakPatternDetector,
  ExfiltrationDetector,
  SubAgentSpawningDetector,
  BaseDetector,
} from './detectors';

export type { PatternMatch } from './detectors';

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
