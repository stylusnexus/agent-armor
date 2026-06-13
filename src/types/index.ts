/**
 * Core types for Agent Armor.
 *
 * Taxonomy based on "AI Agent Traps" (Franklin et al., Google DeepMind, 2026).
 */

// ---------------------------------------------------------------------------
// Threat taxonomy
// ---------------------------------------------------------------------------

export type TrapCategory =
  | "content-injection"
  | "semantic-manipulation"
  | "cognitive-state"
  | "behavioural-control"
  | "systemic"
  | "human-in-the-loop"
  | "transport-integrity";

export type ContentInjectionType =
  | "hidden-html"
  | "metadata-injection"
  | "dynamic-cloaking"
  | "steganographic-payload"
  | "syntactic-masking";

export type SemanticManipulationType =
  | "biased-framing"
  | "oversight-evasion"
  | "persona-hyperstition";

export type CognitiveStateType =
  | "rag-knowledge-poisoning"
  | "latent-memory-poisoning"
  | "contextual-learning-trap";

export type BehaviouralControlType =
  | "embedded-jailbreak"
  | "data-exfiltration"
  | "sub-agent-spawning";

export type SystemicType =
  | "congestion-trap"
  | "interdependence-cascade"
  | "tacit-collusion"
  | "compositional-fragment"
  | "sybil-attack";

export type HumanInTheLoopType = "approval-fatigue" | "social-engineering";

export type TransportIntegrityType =
  | "tool-call-tampering"
  | "credential-exposure"
  | "dependency-substitution"
  | "response-anomaly";

export type TrapType =
  | ContentInjectionType
  | SemanticManipulationType
  | CognitiveStateType
  | BehaviouralControlType
  | SystemicType
  | HumanInTheLoopType
  | TransportIntegrityType;

// ---------------------------------------------------------------------------
// Severity & confidence
// ---------------------------------------------------------------------------

export type Severity = "low" | "medium" | "high" | "critical";

/** 0-1 confidence score from a detector */
export type Confidence = number;

export type ThreatSource = "pattern" | "ml" | "custom";

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
  /** Where this threat was detected: pattern (regex), ml (classifier), or custom */
  source: ThreatSource;
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
// Multi-turn / session scanning (#35)
// ---------------------------------------------------------------------------

/** A single message in a multi-turn conversation passed to scanSession. */
export interface ConversationTurn {
  /** Who/what produced this turn. */
  role: "user" | "assistant" | "tool" | "document" | "system";
  /** The turn's text content. */
  content: string;
}

/**
 * A threat that only emerges across multiple turns (cross-turn decomposition):
 * a payload split across a turn boundary, or signal accumulated over turns.
 * It has no single-string offset, so `location` is omitted and `evidence`
 * carries one snippet; `contributingTurns` records which turns fed it.
 */
export interface CrossTurnThreat extends Omit<Threat, "location"> {
  /** Indices (into the scanned turn array) that contributed to this threat. */
  contributingTurns: number[];
  /** Running confidence total that crossed the reporting threshold. */
  accumulatedConfidence: number;
}

/**
 * Result of scanning a multi-turn conversation. `turns` holds the per-turn
 * single-string results (identical to scanning each turn on its own);
 * `crossTurnThreats` holds threats that only the session view reveals.
 *
 * Note: a session has no single sanitized form — per-turn sanitized text lives
 * on each entry in `turns`; cross-turn threats are advisory.
 */
export interface SessionScanResult {
  /** Whether the session is free of both per-turn and cross-turn threats. */
  clean: boolean;
  /** Per-turn scan results, in the order the turns were supplied. */
  turns: ScanResult[];
  /** Threats that only emerge when turns are considered together. */
  crossTurnThreats: CrossTurnThreat[];
  /** Time taken in milliseconds for the whole session scan. */
  durationMs: number;
  /** Summary stats for the session. */
  stats: {
    turnsScanned: number;
    /** Total chars considered in the cross-turn window (0 until Phase 1). */
    windowChars: number;
    threatsFound: number;
    crossTurnThreatsFound: number;
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
  /** Async scan method (used by ML detectors where inference is async) */
  scanAsync?(
    content: string,
    options?: DetectorOptions,
  ): Promise<DetectorResult>;
}

export interface DetectorOptions {
  /** Override default strictness */
  strictness?: Strictness;
}

export interface DetectorResult {
  threats: Threat[];
}

// ---------------------------------------------------------------------------
// ML configuration
// ---------------------------------------------------------------------------

export type ModelErrorCode =
  | "MODEL_NOT_FOUND"
  | "CHECKSUM_MISMATCH"
  | "DOWNLOAD_FAILED"
  | "DOWNLOAD_TIMEOUT"
  | "DISK_FULL"
  | "LOCK_TIMEOUT";

export interface MLDownloadConfig {
  /** Download timeout in ms (default: 120_000) */
  timeoutMs?: number;
  /** Number of retry attempts (default: 2) */
  retries?: number;
  /** Progress callback */
  onProgress?: (bytesReceived: number, totalBytes: number) => void;
}

export interface MLConfig {
  /** Enable ML classifier (downloads model on first use) */
  enabled?: boolean;
  /** Local directory containing ONNX model + tokenizer files */
  modelDir?: string;
  /** Inject a custom Detector (skips model download, useful for testing) */
  detector?: Detector;
  /** Behavior when ML model is unavailable */
  onUnavailable?: "throw" | "warn-and-skip" | "silent-skip";
  /** API key for Pro tier pattern/model updates (future) */
  apiKey?: string;
  /** Custom model download URL (future) */
  modelUrl?: string;
  /** Download configuration */
  download?: MLDownloadConfig;
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

export type Strictness = "permissive" | "balanced" | "strict";

export interface AgentArmorConfig {
  strictness?: Strictness;
  /**
   * Apply Unicode normalization (NFKC + confusable folding + invisible-char
   * stripping) before semantic detectors run, so homoglyph-obfuscated payloads
   * are matched. Evidence and offsets still report against the original text.
   * Structural detectors (content-injection) always scan the raw input.
   * Default: true.
   */
  normalizeUnicode?: boolean;
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
  cognitiveState?: {
    ragPoisoning?: boolean;
    memoryPoisoning?: boolean;
    contextualLearning?: boolean;
  };
  semanticManipulation?: {
    biasedFraming?: boolean;
    oversightEvasion?: boolean;
    personaHyperstition?: boolean;
  };
  transportIntegrity?: {
    toolCallTampering?: boolean;
    credentialExposure?: boolean;
    dependencySubstitution?: boolean;
    responseAnomaly?: boolean;
  };
  /** Custom detectors to add to the pipeline */
  customDetectors?: Detector[];
  /** ML classifier configuration (requires @stylusnexus/agentarmor-ml) */
  ml?: MLConfig;
  /** Multi-turn / session scanning configuration (#35) */
  session?: SessionConfig;
}

export interface SessionConfig {
  /**
   * Max recent turns kept in the cross-turn window for split-payload detection
   * (Phase 1). Default: 8.
   */
  windowTurns?: number;
  /**
   * Character budget for the cross-turn window (Phase 1). Older turns drop out
   * once the budget is exceeded. Default: 4000.
   */
  windowChars?: number;
  /**
   * Enable cross-turn signal accumulation (Phase 2) — gradual memory poisoning
   * and contextual-learning drift. Opt-in because accumulation carries the
   * highest false-positive risk. Default: false.
   */
  accumulation?: boolean;
  /**
   * Per-turn decay (0-1) applied to accumulated signal so stale turns fade
   * (Phase 2, only used when `accumulation` is true). Default: 0.5.
   */
  decay?: number;
}
