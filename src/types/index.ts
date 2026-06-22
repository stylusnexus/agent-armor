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

/**
 * Single roll-up risk assessment for a scan, computed from the dominant threat
 * (highest severity + its confidence). Gives integrators a one-line allow/deny
 * decision without iterating threats. `none` means no threats were found.
 */
export type RiskLevel = "none" | "low" | "medium" | "high" | "critical";

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
  /**
   * Single roll-up risk assessment derived from the dominant threat. `none`
   * when `clean` is true. Lets integrators decide with one comparison
   * (`if (result.riskLevel === 'critical') block()`).
   */
  riskLevel: RiskLevel;
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
    /** Total chars considered in the cross-turn split-payload window. */
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

// ---------------------------------------------------------------------------
// Pre-execution action gate (#57)
// ---------------------------------------------------------------------------

/**
 * One entry in a positive allowlist of permitted agent actions. A request is
 * admissible only if it matches a rule's `tool` exactly AND satisfies every
 * constraint present on that rule. Constraints left undefined are unconstrained
 * — a bare `{ tool: 'fs.read' }` admits ANY args for that tool, so add the
 * `hosts`/`paths`/`mode` constraints the tool needs.
 */
export interface ActionRule {
  /** Exact tool / operation name this rule permits (e.g. `'http.get'`). */
  tool: string;
  /**
   * Allowed hosts. The request host is taken from the hostname of `args.url`
   * (what an HTTP tool actually fetches); `args.host` is consulted only when no
   * `args.url` is present, and if both are given and disagree the request is
   * denied. Each entry is an exact host or a leading-wildcard subdomain
   * (`'*.example.com'`, which also matches the apex `example.com`). A trailing
   * FQDN dot is ignored. If set and no host can be determined, the request is
   * denied.
   */
  hosts?: string[];
  /**
   * Allowed paths as globs (see {@link matchGlob}). Matched against `args.path`,
   * which must be an already-decoded, relative path. The gate fails closed on
   * absolute paths, parent-directory traversal (`..`), percent-encoding, and
   * non-ASCII (it never resolves paths against a trusted base). If set and
   * `args.path` is absent or matches none, the request is denied.
   */
  paths?: string[];
  /**
   * Required access mode. `'read-only'` denies any request that signals a write:
   * `args.mode` of `'write'`/`'read-write'`, `args.write === true`,
   * `args.readOnly === false`, or an HTTP `args.method` other than
   * GET/HEAD/OPTIONS. This is a known-signal check, not content inspection — it
   * does not parse SQL/command bodies. `'read-write'` imposes no mode constraint.
   */
  mode?: "read-only" | "read-write";
}

/** A proposed agent action evaluated by {@link AgentArmor.checkAction}. */
export interface ActionRequest {
  /** The tool / operation the agent proposes to run. */
  tool: string;
  /**
   * Tool arguments. The gate inspects `url`/`host` (host constraint), `path`
   * (path constraint), and `mode`/`write`/`readOnly` (mode constraint).
   */
  args?: Record<string, unknown>;
}

/** The deterministic verdict from {@link AgentArmor.checkAction}. */
export interface ActionVerdict {
  /** True only if the request matched a rule and satisfied all its constraints. */
  admissible: boolean;
  /** Human-readable explanation. Always set when `admissible` is false. */
  reason?: string;
  /** The rule that admitted the request, when `admissible` is true. */
  matchedRule?: ActionRule;
}

export interface AgentArmorConfig {
  strictness?: Strictness;
  /**
   * Positive allowlist for the pre-execution action gate (#57). When set,
   * {@link AgentArmor.checkAction} admits only requests matching one of these
   * rules; everything else fails closed. An empty array denies all actions.
   */
  allowedActions?: ActionRule[];
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
   * Max recent turns kept in the cross-turn window for split-payload detection.
   * Default: 8.
   */
  windowTurns?: number;
  /**
   * Character budget for the cross-turn split-payload window. Older turns drop
   * out once the budget is exceeded. Default: 4000.
   */
  windowChars?: number;
  /**
   * Cross-turn signal accumulation — gradual memory poisoning and
   * contextual-learning drift. Default: false.
   *
   * Handled by the ML classifier, NOT regex: a regex signal cannot separate a
   * malicious standing "always downplay risk" rule from legitimate reassurance
   * scripting without an unacceptable false-positive rate (the distinction is
   * semantic, not lexical). When enabled AND the ML classifier is active, the
   * async path (`scanSessionAsync`) shows the model a sliding window of recent
   * turns so accumulated signal can surface on its accumulation labels. On the
   * regex-only SDK or the sync path the flag is inert and warns once;
   * split-payload detection is unaffected either way.
   */
  accumulation?: boolean;
  /**
   * Per-turn decay (0-1) reserved for accumulation (see `accumulation`; not
   * active in the regex SDK). Default: 0.5.
   */
  decay?: number;
}
