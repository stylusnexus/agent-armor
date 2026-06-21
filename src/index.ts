export { AgentArmor, computeRiskLevel } from './agent-armor';

// Pre-execution action gate (#57)
export { ActionBlockedError, evaluateAction } from './action-gate';
export { matchGlob, globToRegExp } from './glob';

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
  ActionRequest,
  ActionRule,
  ActionVerdict,
  AgentArmorConfig,
  Confidence,
  ConversationTurn,
  CrossTurnThreat,
  Detector,
  DetectorOptions,
  DetectorResult,
  MLConfig,
  MLDownloadConfig,
  ModelErrorCode,
  RiskLevel,
  ScanResult,
  SessionConfig,
  SessionScanResult,
  Severity,
  Strictness,
  Threat,
  ThreatSource,
  TrapCategory,
  TrapType,
  ContentInjectionType,
  SemanticManipulationType,
  CognitiveStateType,
  BehaviouralControlType,
  TransportIntegrityType,
  SystemicType,
  HumanInTheLoopType,
} from './types';
