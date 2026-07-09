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

/** Content Injection trap subtypes (perception-layer attacks). */
export type ContentInjectionType =
  | "hidden-html"
  | "metadata-injection"
  | "dynamic-cloaking"
  | "steganographic-payload"
  | "syntactic-masking";

/** Semantic Manipulation trap subtypes (reasoning-layer attacks). */
export type SemanticManipulationType =
  | "biased-framing"
  | "oversight-evasion"
  | "persona-hyperstition";

/** Cognitive State trap subtypes (memory-layer attacks). */
export type CognitiveStateType =
  | "rag-knowledge-poisoning"
  | "latent-memory-poisoning"
  | "contextual-learning-trap";

/** Behavioural Control trap subtypes (action-layer attacks). */
export type BehaviouralControlType =
  | "embedded-jailbreak"
  | "data-exfiltration"
  | "sub-agent-spawning";

/** Systemic trap subtypes (multi-agent-layer attacks). */
export type SystemicType =
  | "congestion-trap"
  | "interdependence-cascade"
  | "tacit-collusion"
  | "compositional-fragment"
  | "sybil-attack";

/** Human-in-the-Loop trap subtypes (overseer-layer attacks). */
export type HumanInTheLoopType = "approval-fatigue" | "social-engineering";

/** Transport Integrity trap subtypes (malicious-intermediary attacks, Liu et al. 2026). */
export type TransportIntegrityType =
  | "tool-call-tampering"
  | "credential-exposure"
  | "dependency-substitution"
  | "response-anomaly";

/** Union of every specific trap subtype across all seven categories. */
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

/** How dangerous a threat is if exploited, independent of detector confidence. */
export type Severity = "low" | "medium" | "high" | "critical";

/**
 * Single roll-up risk assessment for a scan, computed from the dominant threat
 * (highest severity + its confidence). Gives integrators a one-line allow/deny
 * decision without iterating threats. `none` means no threats were found.
 */
export type RiskLevel = "none" | "low" | "medium" | "high" | "critical";

/** 0-1 confidence score from a detector */
export type Confidence = number;

/** Where a threat was detected: pattern (regex), ml (classifier), or custom. */
export type ThreatSource = "pattern" | "ml" | "custom";

// ---------------------------------------------------------------------------
// Threat descriptor
// ---------------------------------------------------------------------------

/** A single detected threat within scanned content. */
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

/** The result of scanning one piece of content for agent traps. */
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

/** The interface every detector (pattern-based, ML, or custom) implements. */
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

/** Per-scan options passed to a detector. */
export interface DetectorOptions {
  /** Override default strictness */
  strictness?: Strictness;
}

/** What a single detector's scan pass returns. */
export interface DetectorResult {
  /** Threats this detector found in the scanned content. */
  threats: Threat[];
}

// ---------------------------------------------------------------------------
// ML configuration
// ---------------------------------------------------------------------------

/** Error codes {@link AgentArmorModelError} can carry when ML model resolution fails. */
export type ModelErrorCode =
  | "MODEL_NOT_FOUND"
  | "CHECKSUM_MISMATCH"
  | "DOWNLOAD_FAILED"
  | "DOWNLOAD_TIMEOUT"
  | "DISK_FULL"
  | "LOCK_TIMEOUT";

/** Options controlling how the ML model is downloaded on first use. */
export interface MLDownloadConfig {
  /** Download timeout in ms (default: 120_000) */
  timeoutMs?: number;
  /** Number of retry attempts (default: 2) */
  retries?: number;
  /** Progress callback */
  onProgress?: (bytesReceived: number, totalBytes: number) => void;
}

/** ML classifier configuration, passed as `config.ml` to {@link AgentArmor.create}. */
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

/** Confidence-threshold preset controlling how aggressively detectors report. */
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

// ---------------------------------------------------------------------------
// Diagnostics / event system (#24)
// ---------------------------------------------------------------------------

/** Fired for expected-but-degraded conditions (e.g. ML unavailable, a feature no-op). */
export interface WarnEvent {
  /** Human-readable message — identical text to what would otherwise go to console.warn. */
  message: string;
  /** Structured context for the condition, when available (e.g. which detector). */
  context?: Record<string, unknown>;
}

/** Fired when something unexpected happened and was caught (e.g. a detector threw). */
export interface ErrorEvent {
  /** Human-readable message — identical text to what would otherwise go to console.warn. */
  message: string;
  /** The actual caught error, for stack traces / instanceof checks / Sentry, etc. */
  error: Error;
  /** Structured context for the condition, when available (e.g. which detector). */
  context?: Record<string, unknown>;
}

/** Fired when a detector was not loaded into the pipeline. */
export interface DetectorSkippedEvent {
  /** The detector's registry id (matches {@link Threat.detectorId} when it does run). */
  detectorId: string;
  /** Why it was skipped: an explicit config toggle, or no patterns for it in the loaded database. */
  reason: "config-disabled" | "no-patterns";
}

/** One threat as recorded on an {@link AuditRecord} — never the raw snippet unless `includeEvidence` was set. */
export interface AuditThreatSummary {
  category: TrapCategory;
  type: TrapType;
  severity: Severity;
  confidence: Confidence;
  detectorId: string;
  source: ThreatSource;
  location?: { offset: number; length: number };
  /** sha256 of the threat's evidence snippet, e.g. `"sha256:ab12..."`. */
  evidenceHash: string;
  /** The raw evidence snippet — present only when the scan call passed `includeEvidence: true`. */
  evidence?: string;
}

/**
 * A durable, structured record of one scan decision — the substrate for
 * SOC2/ISO27001-style audit trails (#38). `decision` is Agent Armor's own
 * classification derived from `riskLevel`, NOT a guarantee of what your
 * application actually did with the `ScanResult` — that decision happens in
 * your code, after the scan call returns, where the SDK can't observe it.
 */
export interface AuditRecord {
  /** Record format version, for forward compatibility. */
  schemaVersion: "audit-record.v1";
  /** ISO 8601 timestamp of when this scan decision completed. */
  timestamp: string;
  /** Unique id for this specific decision (one per chunk/turn, not per API call). */
  scanId: string;
  /** Shared across every record from the same top-level call (e.g. all chunks in one scanRAGChunks call). Undefined for single-content calls. */
  batchId?: string;
  /** Which SDK entry point produced this record. */
  source: "scanSync" | "scan" | "scanRAGChunks" | "scanOutput" | "scanSession";
  /** Chunk index (scanRAGChunks) or turn index (scanSession). Undefined for single-content calls. */
  index?: number;
  /** Agent Armor's classification of this scan — see the interface doc comment above. */
  decision: "allow" | "sanitize" | "block" | "exception";
  /** Confidence-threshold preset active for this scan. */
  strictness: Strictness;
  /** Pattern database version that produced this decision. */
  patternDbVersion: string;
  /** ML model version, present only when the ML classifier ran for this scan. */
  mlModelVersion?: string;
  /** Unique categories among detected threats. */
  categories: TrapCategory[];
  /** Per-threat summaries — see {@link AuditThreatSummary}. */
  threats: AuditThreatSummary[];
  /** Populated only when `decision === 'exception'` — both fields required (cannot omit reason or actor). */
  exception?: { reason: string; actor: string };
  /** Scan duration in ms. */
  durationMs: number;
}

/**
 * Options accepted by every scan method (`scanSync`, `scan`, `scanRAGChunks(Sync)`,
 * `scanOutput(Sync)`, `scanSession(Async)`) as an optional second/last parameter.
 */
export interface ScanOptions {
  /**
   * Marks this scan as a known, intentional override — you've already decided
   * to let this content through despite risk, and want that decision captured
   * on the audit record instead of the auto-derived allow/sanitize/block.
   */
  exception?: { reason: string; actor: string };
  /**
   * Include the raw offending snippet (not just its hash) on the audit record.
   * Opt-in only — carries the data-handling responsibility of storing content
   * in your audit sink. Default: false.
   */
  includeEvidence?: boolean;
}

/**
 * Aggregates many {@link AuditRecord}s into a single tamper-evident summary
 * for a reporting period — built by {@link buildEvidencePackage}, checked by
 * {@link verifyEvidencePackage}. See #75 / the marywang-aiops design comment
 * on #24 for the three-layer model this implements (event record / evidence
 * package / control claim).
 */
export interface EvidencePackage {
  schemaVersion: "audit-evidence-package.v1";
  periodStart: string;
  periodEnd: string;
  recordCount: number;
  decisionCounts: Record<AuditRecord["decision"], number>;
  /** e.g. `["patterns@0.6.0", "ml@v1"]` — every distinct version combination seen. */
  detectorVersions: string[];
  /** scanIds of every exception-decision record, for quick review. */
  exceptionRecordIds: string[];
  /** True if any record in the package has `includeEvidence`-populated raw evidence. */
  rawContentStored: boolean;
  /** sha256 over the records in order — any edit to any record changes this. */
  packageDigest: string;
}

/**
 * Diagnostics callbacks, passed as `config.on`. Routes internal diagnostics to your
 * own logging/alerting instead of `console.warn`. Fully opt-in: with no `on` config,
 * behavior is identical to not having this feature — every event still reaches
 * `console.warn` exactly as before.
 */
export interface DiagnosticsConfig {
  /** Expected-but-degraded conditions (ML unavailable, a config no-op, etc.). */
  warn?: (event: WarnEvent) => void;
  /** Unexpected caught errors (a detector threw during scan). */
  error?: (event: ErrorEvent) => void;
  /** A detector was not loaded into the pipeline. */
  detectorSkipped?: (event: DetectorSkippedEvent) => void;
  /** One durable record per scan decision — see {@link AuditRecord}. */
  audit?: (record: AuditRecord) => void;
}

/** Configuration passed to {@link AgentArmor.regexOnly} or {@link AgentArmor.create}. */
export interface AgentArmorConfig {
  /** Confidence-threshold preset. Default: `'balanced'`. */
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
  /** Per-detector toggles within the Content Injection category. All default true. */
  contentInjection?: {
    hiddenHTML?: boolean;
    metadataInjection?: boolean;
    dynamicCloaking?: boolean;
    syntacticMasking?: boolean;
  };
  /** Per-detector toggles within the Behavioural Control category. All default true. */
  behaviouralControl?: {
    jailbreakPatterns?: boolean;
    exfiltrationURLs?: boolean;
    privilegeEscalation?: boolean;
  };
  /** Per-detector toggles within the Cognitive State category. All default true. */
  cognitiveState?: {
    ragPoisoning?: boolean;
    memoryPoisoning?: boolean;
    contextualLearning?: boolean;
  };
  /** Per-detector toggles within the Semantic Manipulation category. All default true. */
  semanticManipulation?: {
    biasedFraming?: boolean;
    oversightEvasion?: boolean;
    personaHyperstition?: boolean;
  };
  /** Per-detector toggles within the Transport Integrity category. All default true. */
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
  /** Diagnostics callbacks — route internal warnings/errors to your own logging (#24). */
  on?: DiagnosticsConfig;
}

/** Multi-turn / session scanning configuration, passed as `config.session` (#35). */
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
   * Reserved for cross-turn signal accumulation — gradual memory poisoning and
   * contextual-learning drift. Default: false.
   *
   * NOT AVAILABLE in the regex SDK: a regex signal cannot separate a malicious
   * standing "always downplay risk" rule from legitimate reassurance scripting
   * without an unacceptable false-positive rate (the distinction is semantic,
   * not lexical). This is planned for the ML classifier. Enabling it here has no
   * effect and emits a one-time warning; split-payload detection is unaffected.
   */
  accumulation?: boolean;
  /**
   * Per-turn decay (0-1) reserved for accumulation (see `accumulation`; not
   * active in the regex SDK). Default: 0.5.
   */
  decay?: number;
}
