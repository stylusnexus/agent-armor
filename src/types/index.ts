/**
 * Core types for Agent Armor.
 *
 * Taxonomy based on "AI Agent Traps" (Franklin et al., Google DeepMind, 2025).
 */

// ---------------------------------------------------------------------------
// Threat taxonomy
// ---------------------------------------------------------------------------

export type TrapCategory =
  | 'content-injection'
  | 'semantic-manipulation'
  | 'cognitive-state'
  | 'behavioural-control'
  | 'systemic'
  | 'human-in-the-loop';

export type ContentInjectionType =
  | 'hidden-html'
  | 'metadata-injection'
  | 'dynamic-cloaking'
  | 'steganographic-payload'
  | 'syntactic-masking';

export type SemanticManipulationType =
  | 'biased-framing'
  | 'oversight-evasion'
  | 'persona-hyperstition';

export type CognitiveStateType =
  | 'rag-knowledge-poisoning'
  | 'latent-memory-poisoning'
  | 'contextual-learning-trap';

export type BehaviouralControlType =
  | 'embedded-jailbreak'
  | 'data-exfiltration'
  | 'sub-agent-spawning';

export type SystemicType =
  | 'congestion-trap'
  | 'interdependence-cascade'
  | 'tacit-collusion'
  | 'compositional-fragment'
  | 'sybil-attack';

export type HumanInTheLoopType =
  | 'approval-fatigue'
  | 'social-engineering';

export type TrapType =
  | ContentInjectionType
  | SemanticManipulationType
  | CognitiveStateType
  | BehaviouralControlType
  | SystemicType
  | HumanInTheLoopType;

// ---------------------------------------------------------------------------
// Severity & confidence
// ---------------------------------------------------------------------------

export type Severity = 'low' | 'medium' | 'high' | 'critical';

/** 0-1 confidence score from a detector */
export type Confidence = number;

// ---------------------------------------------------------------------------
// Threat descriptor
// ---------------------------------------------------------------------------

export interface Threat {
  /** Which category from the DeepMind taxonomy */
  category: TrapCategory;
  /** Specific trap type within the category */
  type: TrapType;
  /** How dangerous this threat is if exploited */
  severity: Severity;
  /** How confident the detector is (0-1) */
  confidence: Confidence;
  /** Human-readable description of the threat */
  description: string;
  /** The offending content snippet (truncated) */
  evidence: string;
  /** Byte offset or line number in the original content, if applicable */
  location?: { offset: number; length: number };
  /** Which detector found this */
  detectorId: string;
}

// ---------------------------------------------------------------------------
// Scan results
// ---------------------------------------------------------------------------

export interface ScanResult {
  /** Whether any threats were found */
  clean: boolean;
  /** All detected threats, sorted by severity desc */
  threats: Threat[];
  /** Sanitized version of the content with threats neutralized */
  sanitized: string;
  /** Time taken in milliseconds */
  durationMs: number;
  /** Summary stats */
  stats: {
    detectorsRun: number;
    threatsFound: number;
    highestSeverity: Severity | null;
  };
}

// ---------------------------------------------------------------------------
// Detector interface
// ---------------------------------------------------------------------------

export interface Detector {
  /** Unique identifier for this detector */
  id: string;
  /** Human-readable name */
  name: string;
  /** Which trap category this detector addresses */
  category: TrapCategory;
  /** Scan content and return any threats found */
  scan(content: string, options?: DetectorOptions): DetectorResult;
  /** Return sanitized content with threats neutralized */
  sanitize(content: string, threats: Threat[]): string;
}

export interface DetectorOptions {
  /** Override default strictness */
  strictness?: Strictness;
}

export interface DetectorResult {
  threats: Threat[];
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

export type Strictness = 'permissive' | 'balanced' | 'strict';

export interface AgentArmorConfig {
  strictness?: Strictness;
  contentInjection?: {
    hiddenHTML?: boolean;
    metadataInjection?: boolean;
    dynamicCloaking?: boolean;
    syntacticMasking?: boolean;
  };
  behaviouralControl?: {
    jailbreakPatterns?: boolean;
    exfiltrationURLs?: boolean;
    privilegeEscalation?: boolean;
  };
  /** Custom detectors to add to the pipeline */
  customDetectors?: Detector[];
}
