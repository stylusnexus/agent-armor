import type {
  AgentArmorConfig,
  ConversationTurn,
  CrossTurnThreat,
  Detector,
  MLConfig,
  ScanResult,
  SessionScanResult,
  Severity,
  Strictness,
  Threat,
  TrapCategory,
  TrapType,
} from './types';
import type { PatternDatabase, PatternEntry } from './patterns/pattern-db';
import { compilePattern } from './patterns/pattern-db';
import {
  DEFAULT_PATTERNS,
  CROSS_TURN_SIGNAL_PATTERNS,
} from './patterns/default-patterns';
import { PatternDetector } from './detectors/pattern-detector';
import {
  normalizeForScan,
  mapRangeToOriginal,
  type NormalizedText,
} from './normalize/unicode';

const DEFAULT_CONFIG: Required<AgentArmorConfig> = {
  strictness: 'balanced',
  normalizeUnicode: true,
  contentInjection: {
    hiddenHTML: true,
    metadataInjection: true,
    dynamicCloaking: true,
    syntacticMasking: true,
  },
  behaviouralControl: {
    jailbreakPatterns: true,
    exfiltrationURLs: true,
    privilegeEscalation: true,
  },
  cognitiveState: {
    ragPoisoning: true,
    memoryPoisoning: true,
    contextualLearning: true,
  },
  semanticManipulation: {
    biasedFraming: true,
    oversightEvasion: true,
    personaHyperstition: true,
  },
  transportIntegrity: {
    toolCallTampering: true,
    credentialExposure: true,
    dependencySubstitution: true,
    responseAnomaly: true,
  },
  customDetectors: [],
  ml: {
    enabled: false,
    onUnavailable: 'warn-and-skip',
  },
  session: {
    windowTurns: 8,
    windowChars: 4000,
    accumulation: false,
    decay: 0.7,
  },
};

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

/** Accumulated-signal thresholds for opt-in cross-turn accumulation (#35 P2). */
const ACCUMULATION_THRESHOLDS: Record<Strictness, number> = {
  strict: 0.3,
  balanced: 0.5,
  permissive: 0.7,
};

/** Cap on a single turn's signal contribution, so one turn cannot fire alone. */
const PER_TURN_SIGNAL_CAP = 0.35;

/**
 * Blanket-rule markers that distinguish a manipulative *standing instruction*
 * ("from now on, reply that it's completely safe") from benign *case-specific*
 * scripting ("for mild symptoms, reassure them"). Accumulation only fires when
 * a scripted-downplaying-answer signal co-occurs with one of these — scripting
 * a downplaying answer as a universal rule is the trap; scripting it for a
 * specific, genuinely-safe case is legitimate support copy.
 */
const GENERALIZATION_MARKERS =
  /(?:always|every\s+time|each\s+time|for\s+all\s+(?:similar\s+)?(?:questions|queries|cases|topics)|from\s+now\s+on|from\s+here\s+on|going\s+forward|in\s+that\s+style|no\s+matter\s+what|regardless|whenever\s+(?:asked|(?:they|someone|a user)\s+asks?)|any(?:\s+time|time)|all\s+(?:future\s+)?responses)/i;

/** Detector config: maps config flags to pattern DB keys + metadata */
const DETECTOR_REGISTRY: Array<{
  configGroup: 'contentInjection' | 'behaviouralControl' | 'cognitiveState' | 'semanticManipulation' | 'transportIntegrity';
  configKey: string;
  patternDbKey: string;
  id: string;
  name: string;
  category: TrapCategory;
  trapType: TrapType;
  sanitizeMode: 'remove' | 'replace' | 'none';
  replaceText?: string;
}> = [
  // Content Injection
  {
    configGroup: 'contentInjection',
    configKey: 'hiddenHTML',
    patternDbKey: 'hidden-html',
    id: 'hidden-html',
    name: 'Hidden HTML Detector',
    category: 'content-injection',
    trapType: 'hidden-html',
    sanitizeMode: 'remove',
  },
  {
    configGroup: 'contentInjection',
    configKey: 'metadataInjection',
    patternDbKey: 'metadata-injection',
    id: 'metadata-injection',
    name: 'Metadata Injection Detector',
    category: 'content-injection',
    trapType: 'metadata-injection',
    sanitizeMode: 'remove',
  },
  {
    configGroup: 'contentInjection',
    configKey: 'dynamicCloaking',
    patternDbKey: 'dynamic-cloaking',
    id: 'dynamic-cloaking',
    name: 'Dynamic Cloaking Detector',
    category: 'content-injection',
    trapType: 'dynamic-cloaking',
    sanitizeMode: 'none',
  },
  {
    configGroup: 'contentInjection',
    configKey: 'syntacticMasking',
    patternDbKey: 'syntactic-masking',
    id: 'syntactic-masking',
    name: 'Syntactic Masking Detector',
    category: 'content-injection',
    trapType: 'syntactic-masking',
    sanitizeMode: 'remove',
  },
  // Behavioural Control
  {
    configGroup: 'behaviouralControl',
    configKey: 'jailbreakPatterns',
    patternDbKey: 'jailbreak-patterns',
    id: 'jailbreak-patterns',
    name: 'Jailbreak Pattern Detector',
    category: 'behavioural-control',
    trapType: 'embedded-jailbreak',
    sanitizeMode: 'replace',
    replaceText:
      '[BLOCKED: potential jailbreak sequence removed by AgentArmor]',
  },
  {
    configGroup: 'behaviouralControl',
    configKey: 'exfiltrationURLs',
    patternDbKey: 'exfiltration',
    id: 'exfiltration',
    name: 'Data Exfiltration Detector',
    category: 'behavioural-control',
    trapType: 'data-exfiltration',
    sanitizeMode: 'replace',
    replaceText:
      '[BLOCKED: exfiltration instruction removed by AgentArmor]',
  },
  {
    configGroup: 'behaviouralControl',
    configKey: 'privilegeEscalation',
    patternDbKey: 'sub-agent-spawning',
    id: 'sub-agent-spawning',
    name: 'Sub-Agent Spawning Detector',
    category: 'behavioural-control',
    trapType: 'sub-agent-spawning',
    sanitizeMode: 'replace',
    replaceText:
      '[BLOCKED: agent spawning instruction removed by AgentArmor]',
  },
  // Cognitive State
  {
    configGroup: 'cognitiveState',
    configKey: 'ragPoisoning',
    patternDbKey: 'rag-knowledge-poisoning',
    id: 'rag-knowledge-poisoning',
    name: 'RAG Knowledge Poisoning Detector',
    category: 'cognitive-state',
    trapType: 'rag-knowledge-poisoning',
    sanitizeMode: 'replace',
    replaceText:
      '[BLOCKED: RAG poisoning content removed by AgentArmor]',
  },
  {
    configGroup: 'cognitiveState',
    configKey: 'memoryPoisoning',
    patternDbKey: 'latent-memory-poisoning',
    id: 'latent-memory-poisoning',
    name: 'Latent Memory Poisoning Detector',
    category: 'cognitive-state',
    trapType: 'latent-memory-poisoning',
    sanitizeMode: 'replace',
    replaceText:
      '[BLOCKED: memory poisoning content removed by AgentArmor]',
  },
  {
    configGroup: 'cognitiveState',
    configKey: 'contextualLearning',
    patternDbKey: 'contextual-learning-trap',
    id: 'contextual-learning-trap',
    name: 'Contextual Learning Trap Detector',
    category: 'cognitive-state',
    trapType: 'contextual-learning-trap',
    sanitizeMode: 'replace',
    replaceText:
      '[BLOCKED: manipulated few-shot content removed by AgentArmor]',
  },
  // Semantic Manipulation
  {
    configGroup: 'semanticManipulation',
    configKey: 'biasedFraming',
    patternDbKey: 'biased-framing',
    id: 'biased-framing',
    name: 'Biased Framing Detector',
    category: 'semantic-manipulation',
    trapType: 'biased-framing',
    sanitizeMode: 'replace',
    replaceText:
      '[BLOCKED: biased framing content removed by AgentArmor]',
  },
  {
    configGroup: 'semanticManipulation',
    configKey: 'oversightEvasion',
    patternDbKey: 'oversight-evasion',
    id: 'oversight-evasion',
    name: 'Oversight Evasion Detector',
    category: 'semantic-manipulation',
    trapType: 'oversight-evasion',
    sanitizeMode: 'replace',
    replaceText:
      '[BLOCKED: oversight evasion content removed by AgentArmor]',
  },
  {
    configGroup: 'semanticManipulation',
    configKey: 'personaHyperstition',
    patternDbKey: 'persona-hyperstition',
    id: 'persona-hyperstition',
    name: 'Persona Hyperstition Detector',
    category: 'semantic-manipulation',
    trapType: 'persona-hyperstition',
    sanitizeMode: 'replace',
    replaceText:
      '[BLOCKED: persona manipulation content removed by AgentArmor]',
  },
];

export class AgentArmor {
  private config: Required<AgentArmorConfig>;
  private detectors: Detector[] = [];
  private patternDb: PatternDatabase;
  private mlDetector: Detector | null = null;
  /** Built-in detector IDs that scan the normalized skeleton, not raw input. */
  private normalizedDetectorIds = new Set<string>();
  /** Lazily compiled cross-turn signal patterns (Phase 2 accumulation). */
  private compiledSignals: Array<{ entry: PatternEntry; regex: RegExp }> | null =
    null;

  constructor(config?: AgentArmorConfig) {
    this.config = {
      ...DEFAULT_CONFIG,
      ...config,
      contentInjection: {
        ...DEFAULT_CONFIG.contentInjection,
        ...config?.contentInjection,
      },
      behaviouralControl: {
        ...DEFAULT_CONFIG.behaviouralControl,
        ...config?.behaviouralControl,
      },
      cognitiveState: {
        ...DEFAULT_CONFIG.cognitiveState,
        ...config?.cognitiveState,
      },
      semanticManipulation: {
        ...DEFAULT_CONFIG.semanticManipulation,
        ...config?.semanticManipulation,
      },
      transportIntegrity: {
        ...DEFAULT_CONFIG.transportIntegrity,
        ...config?.transportIntegrity,
      },
      ml: {
        ...DEFAULT_CONFIG.ml,
        ...config?.ml,
      },
      session: {
        ...DEFAULT_CONFIG.session,
        ...config?.session,
      },
      customDetectors: config?.customDetectors ?? [],
    };

    this.patternDb = DEFAULT_PATTERNS;
    this.loadDetectors();
  }

  /**
   * Create an AgentArmor instance with optional ML classifier.
   * Use this when ML detection is needed (async model loading).
   */
  static async create(config?: AgentArmorConfig): Promise<AgentArmor> {
    const instance = new AgentArmor(config);
    if (instance.config.ml?.enabled || instance.config.ml?.detector) {
      await instance.initML(instance.config.ml);
    }
    return instance;
  }

  /**
   * Create a regex-only AgentArmor instance.
   * Convenience method that makes the sync-only intent explicit.
   */
  static regexOnly(config?: Omit<AgentArmorConfig, 'ml'>): AgentArmor {
    return new AgentArmor(config);
  }

  /**
   * Load a custom pattern database (e.g. from a remote update).
   * Rebuilds all detectors with the new patterns.
   */
  loadPatterns(patterns: PatternDatabase): void {
    this.patternDb = patterns;
    this.detectors = [];
    this.loadDetectors();
    if (this.mlDetector) {
      this.detectors.push(this.mlDetector);
    }
  }

  /**
   * Get the current pattern database version.
   */
  get patternVersion(): string {
    return this.patternDb.version;
  }

  /**
   * Fetch the latest patterns from a remote URL.
   * URL is required — there is no default endpoint.
   */
  static async fetchLatestPatterns(url: string): Promise<PatternDatabase> {
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(
        `Failed to fetch patterns: ${response.status} ${response.statusText}`
      );
    }
    return (await response.json()) as PatternDatabase;
  }

  /**
   * Scan arbitrary content for agent traps (sync).
   */
  scanSync(content: string): ScanResult {
    return this.runScanPipeline(content);
  }

  /**
   * Scan retrieved RAG chunks before prompt assembly (sync).
   */
  scanRAGChunksSync(chunks: string[]): ScanResult[] {
    return chunks.map((chunk) => this.runScanPipeline(chunk));
  }

  /**
   * Scan agent output before it reaches the user (sync).
   */
  scanOutputSync(output: string): ScanResult {
    return this.runScanPipeline(output);
  }

  /**
   * Scan arbitrary content for agent traps (async).
   * Prefers scanAsync on detectors that support it.
   */
  async scan(content: string): Promise<ScanResult> {
    return this.runScanPipelineAsync(content);
  }

  /**
   * Scan retrieved RAG chunks before prompt assembly (async).
   */
  async scanRAGChunks(chunks: string[]): Promise<ScanResult[]> {
    return Promise.all(chunks.map((chunk) => this.runScanPipelineAsync(chunk)));
  }

  /**
   * Scan agent output before it reaches the user (async).
   */
  async scanOutput(output: string): Promise<ScanResult> {
    return this.runScanPipelineAsync(output);
  }

  /**
   * Scan a multi-turn conversation for agent traps (sync).
   *
   * Phase 0: each turn is scanned independently and the results are aggregated.
   * Cross-turn detection (split payloads in Phase 1, signal accumulation in
   * Phase 2) lands behind this same method, so callers do not change.
   */
  scanSession(turns: ConversationTurn[]): SessionScanResult {
    const start = performance.now();
    const perTurn = turns.map((turn) => this.runScanPipeline(turn.content));
    const { crossTurnThreats, windowChars } = this.scanCrossTurn(turns);
    const accumulated = this.config.session.accumulation
      ? this.scanAccumulation(turns)
      : [];
    return this.assembleSession(
      perTurn,
      [...crossTurnThreats, ...accumulated],
      windowChars,
      performance.now() - start
    );
  }

  /**
   * Scan a multi-turn conversation for agent traps (async).
   * Prefers scanAsync on detectors that support it (e.g. the ML classifier).
   */
  async scanSessionAsync(turns: ConversationTurn[]): Promise<SessionScanResult> {
    const start = performance.now();
    const perTurn: ScanResult[] = [];
    for (const turn of turns) {
      perTurn.push(await this.runScanPipelineAsync(turn.content));
    }
    // Cross-turn split-payload detection is pattern-based (needs match offsets
    // to prove a span crosses a turn boundary); the sync window scan is reused.
    // ML threats carry no offsets and so do not produce cross-turn threats.
    const { crossTurnThreats, windowChars } = this.scanCrossTurn(turns);
    const accumulated = this.config.session.accumulation
      ? this.scanAccumulation(turns)
      : [];
    return this.assembleSession(
      perTurn,
      [...crossTurnThreats, ...accumulated],
      windowChars,
      performance.now() - start
    );
  }

  get strictness(): Strictness {
    return this.config.strictness;
  }

  // ---------------------------------------------------------------------------
  // Internal
  // ---------------------------------------------------------------------------

  private async initML(mlConfig: MLConfig): Promise<void> {
    if (mlConfig.detector) {
      this.mlDetector = mlConfig.detector;
      this.detectors.push(this.mlDetector);
      return;
    }

    if (mlConfig.enabled || mlConfig.modelDir) {
      try {
        // @ts-ignore -- @stylusnexus/agentarmor-ml is an optional peer dependency
        const mlModule = await import('@stylusnexus/agentarmor-ml');
        const detector = await mlModule.createMLDetector(mlConfig);
        this.mlDetector = detector;
        this.detectors.push(detector);
      } catch (err) {
        const behavior = mlConfig.onUnavailable ?? 'throw';
        if (behavior === 'throw') {
          throw new Error(
            `ML classifier unavailable: ${err instanceof Error ? err.message : String(err)}. ` +
            `Install @stylusnexus/agentarmor-ml or set ml.onUnavailable to 'warn-and-skip'.`
          );
        } else if (behavior === 'warn-and-skip') {
          console.warn(
            `[AgentArmor] ML classifier unavailable, falling back to regex-only: ${err instanceof Error ? err.message : String(err)}`
          );
        }
      }
    }
  }

  private loadDetectors(): void {
    this.normalizedDetectorIds.clear();
    for (const reg of DETECTOR_REGISTRY) {
      const groupConfig =
        this.config[reg.configGroup] as Record<string, boolean>;
      if (!groupConfig[reg.configKey]) continue;

      const patterns = this.patternDb.detectors[reg.patternDbKey];
      if (!patterns || patterns.length === 0) continue;

      this.detectors.push(
        new PatternDetector({
          id: reg.id,
          name: reg.name,
          category: reg.category,
          trapType: reg.trapType,
          patterns,
          sanitizeMode: reg.sanitizeMode,
          replaceText: reg.replaceText,
        })
      );

      // Structural detectors (content-injection) must see the raw bytes — they
      // exist to catch the invisible/obfuscation characters normalization
      // strips. Everything else scans the normalized skeleton.
      if (reg.category !== 'content-injection') {
        this.normalizedDetectorIds.add(reg.id);
      }
    }

    // Custom detectors
    this.detectors.push(...this.config.customDetectors);
  }

  /** Re-map normalized-space threats back onto the original content. */
  private remapThreats(
    threats: Threat[],
    norm: NormalizedText,
    original: string
  ): Threat[] {
    return threats.map((t) => {
      if (!t.location) return t;
      const location = mapRangeToOriginal(
        norm,
        t.location.offset,
        t.location.length
      );
      const slice = original.slice(
        location.offset,
        location.offset + location.length
      );
      const evidence = slice.length > 200 ? slice.slice(0, 197) + '...' : slice;
      return { ...t, location, evidence };
    });
  }

  private runScanPipeline(content: string): ScanResult {
    const start = performance.now();
    const allThreats: Threat[] = [];
    const norm = this.config.normalizeUnicode
      ? normalizeForScan(content)
      : null;

    for (const detector of this.detectors) {
      const useNorm =
        norm !== null && norm.changed && this.normalizedDetectorIds.has(detector.id);
      const scanInput = useNorm ? norm!.normalized : content;
      try {
        const result = detector.scan(scanInput, {
          strictness: this.config.strictness,
        });
        allThreats.push(
          ...(useNorm
            ? this.remapThreats(result.threats, norm!, content)
            : result.threats)
        );
      } catch (err) {
        console.warn(
          `[AgentArmor] Detector "${detector.id}" threw during scan: ${err instanceof Error ? err.message : String(err)}`
        );
      }
    }

    allThreats.sort((a, b) => {
      const sevDiff = SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity];
      if (sevDiff !== 0) return sevDiff;
      return b.confidence - a.confidence;
    });

    let sanitized = content;
    for (const detector of this.detectors) {
      const relevantThreats = allThreats.filter(
        (t) => t.detectorId === detector.id
      );
      if (relevantThreats.length > 0) {
        sanitized = detector.sanitize(sanitized, relevantThreats);
      }
    }

    const durationMs = performance.now() - start;

    return {
      clean: allThreats.length === 0,
      threats: allThreats,
      sanitized,
      durationMs,
      stats: {
        detectorsRun: this.detectors.length,
        threatsFound: allThreats.length,
        highestSeverity: allThreats[0]?.severity ?? null,
      },
    };
  }

  private async runScanPipelineAsync(content: string): Promise<ScanResult> {
    const start = performance.now();
    const allThreats: Threat[] = [];
    const norm = this.config.normalizeUnicode
      ? normalizeForScan(content)
      : null;

    for (const detector of this.detectors) {
      const useNorm =
        norm !== null && norm.changed && this.normalizedDetectorIds.has(detector.id);
      const scanInput = useNorm ? norm!.normalized : content;
      try {
        if ('scanAsync' in detector && typeof detector.scanAsync === 'function') {
          const result = await detector.scanAsync(scanInput, {
            strictness: this.config.strictness,
          });
          allThreats.push(
            ...(useNorm
              ? this.remapThreats(result.threats, norm!, content)
              : result.threats)
          );
        } else {
          const result = detector.scan(scanInput, {
            strictness: this.config.strictness,
          });
          allThreats.push(
            ...(useNorm
              ? this.remapThreats(result.threats, norm!, content)
              : result.threats)
          );
        }
      } catch (err) {
        console.warn(
          `[AgentArmor] Detector "${detector.id}" threw during scan: ${err instanceof Error ? err.message : String(err)}`
        );
      }
    }

    allThreats.sort((a, b) => {
      const sevDiff = SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity];
      if (sevDiff !== 0) return sevDiff;
      return b.confidence - a.confidence;
    });

    let sanitized = content;
    for (const detector of this.detectors) {
      const relevantThreats = allThreats.filter(
        (t) => t.detectorId === detector.id
      );
      if (relevantThreats.length > 0) {
        sanitized = detector.sanitize(sanitized, relevantThreats);
      }
    }

    const durationMs = performance.now() - start;

    return {
      clean: allThreats.length === 0,
      threats: allThreats,
      sanitized,
      durationMs,
      stats: {
        detectorsRun: this.detectors.length,
        threatsFound: allThreats.length,
        highestSeverity: allThreats[0]?.severity ?? null,
      },
    };
  }

  /**
   * Phase 2 (opt-in) cross-turn signal accumulation: catch contextual-learning
   * drift, where no single turn trips a threshold but a biased answer-scripting
   * signal REPEATS across turns.
   *
   * Each turn is scanned for sub-threshold signal patterns (CROSS_TURN_SIGNAL_
   * PATTERNS — scripted risk-downplaying answer exemplars). Per trap type, a
   * running score accumulates each turn's signal (capped per turn) and decays
   * prior turns by `session.decay`, so the signal must persist to build up. When
   * the running score crosses the strictness threshold AND at least two distinct
   * turns contributed, a cross-turn threat is emitted attributing those turns.
   *
   * Scoped narrowly on purpose: it targets scripting the SUBSTANCE of answers
   * toward downplaying risk, and only when framed as a STANDING rule (a
   * generalization marker like "from now on" / "for all questions" must
   * co-occur) — so case-specific reassurance is not flagged. It does not target
   * preference shaping ("recommend X over the alternatives"), which is
   * indistinguishable from legitimate recommendation and is a documented blind
   * spot. Opt-in because semantic accumulation is inherently lower-precision
   * than structural detection.
   */
  private scanAccumulation(turns: ConversationTurn[]): CrossTurnThreat[] {
    if (turns.length < 2) return [];
    if (!this.compiledSignals) {
      this.compiledSignals = CROSS_TURN_SIGNAL_PATTERNS.map((entry) => ({
        entry,
        regex: compilePattern(entry),
      }));
    }

    const decay = this.config.session.decay ?? 0.7;
    const threshold = ACCUMULATION_THRESHOLDS[this.config.strictness];
    const maxTurns = this.config.session.windowTurns ?? 8;
    const startTurn = Math.max(0, turns.length - maxTurns);
    const types = [...new Set(this.compiledSignals.map((s) => s.entry.type))];

    // A scripted downplaying answer is only treated as a trap when the session
    // also frames it as a STANDING rule ("from now on", "for all questions").
    // Without a generalization marker it reads as case-specific support copy,
    // not manipulation — this is the line that keeps benign reassurance scripts
    // (medical/wellness FAQs) from accumulating into a false positive.
    const hasGeneralization = turns
      .slice(startTurn)
      .some((t) => GENERALIZATION_MARKERS.test(t.content));
    if (!hasGeneralization) return [];

    const out: CrossTurnThreat[] = [];
    for (const type of types) {
      const sigs = this.compiledSignals.filter((s) => s.entry.type === type);
      let running = 0;
      let peak = 0;
      let crossed = false;
      const contributing: number[] = [];
      let topEntry: PatternEntry | null = null;
      let topEvidence = '';

      for (let i = startTurn; i < turns.length; i++) {
        const text = turns[i].content;
        let turnScore = 0;
        for (const s of sigs) {
          s.regex.lastIndex = 0;
          const m = s.regex.exec(text);
          if (m) {
            turnScore += s.entry.confidence;
            if (s.entry.confidence >= (topEntry?.confidence ?? 0)) {
              topEntry = s.entry;
              topEvidence = m[0];
            }
          }
        }
        turnScore = Math.min(turnScore, PER_TURN_SIGNAL_CAP);
        running = running * decay + turnScore;
        if (turnScore > 0) contributing.push(i);
        peak = Math.max(peak, running);
        if (running >= threshold && contributing.length >= 2) crossed = true;
      }

      if (crossed && topEntry) {
        const confidence = Math.min(peak, 1);
        out.push({
          category: topEntry.category,
          type,
          severity: topEntry.severity,
          confidence,
          accumulatedConfidence: confidence,
          description:
            `Cross-turn ${type}: biased signals accumulated across turns ` +
            `${contributing.join(', ')}`,
          evidence: topEvidence.slice(0, 200),
          detectorId: 'session-accumulator',
          source: 'pattern',
          contributingTurns: contributing,
        });
      }
    }
    return out;
  }

  /**
   * Phase 1 cross-turn detection: catch payloads split across a turn boundary.
   *
   * Each adjacent turn boundary (within the trailing `windowTurns` turns) is
   * scanned independently: the tail of the earlier turn and the head of the
   * later turn — each capped at `windowChars` so a padded turn cannot evict its
   * neighbour — are joined and scanned as one string. A threat whose match span
   * crosses the boundary (touches both sides) is a genuine split payload that
   * was invisible to per-turn scanning, and is emitted as a CrossTurnThreat
   * attributing the two turns.
   *
   * Two properties this preserves:
   * - No false positives from benign repetition: a match must straddle the
   *   boundary, so a phrase contained in one turn (already reported per-turn) is
   *   never re-emitted.
   * - No padding evasion: boundary slices are taken from both sides, so filler
   *   in the middle of a turn cannot push the split out of view.
   *
   * Known limitations (documented, narrow): a single phrase split across THREE
   * or more turns is not reunited (only adjacent pairs are joined); and a
   * lookbehind pattern whose consumed span lands wholly on the later side is not
   * treated as cross-turn (the span-straddle rule favours precision over this
   * recall edge). `windowChars` records total chars scanned across boundaries.
   */
  private scanCrossTurn(turns: ConversationTurn[]): {
    crossTurnThreats: CrossTurnThreat[];
    windowChars: number;
  } {
    if (turns.length < 2) return { crossTurnThreats: [], windowChars: 0 };

    const SEP = '\n';
    const maxTurns = this.config.session.windowTurns ?? 8;
    const cap = this.config.session.windowChars ?? 4000;
    // windowTurns < 2 means no cross-turn context: there are no boundaries.
    const firstBoundary = Math.max(0, turns.length - maxTurns);

    const crossTurnThreats: CrossTurnThreat[] = [];
    const seen = new Set<string>();
    let windowChars = 0;

    for (let i = firstBoundary; i < turns.length - 1; i++) {
      const earlier = turns[i].content;
      const later = turns[i + 1].content;
      // Boundary-adjacent slices, each capped so padding cannot hide the join.
      const aSlice =
        earlier.length > cap ? earlier.slice(earlier.length - cap) : earlier;
      const bSlice = later.length > cap ? later.slice(0, cap) : later;

      const joined = aSlice + SEP + bSlice;
      windowChars += joined.length;
      const aEnd = aSlice.length; // earlier turn occupies [0, aEnd)
      const bStart = aEnd + SEP.length; // later turn occupies [bStart, end)

      for (const threat of this.runScanPipeline(joined).threats) {
        if (!threat.location) continue; // no offset → cannot prove a span
        const spanStart = threat.location.offset;
        const spanEnd = spanStart + threat.location.length;
        const touchesEarlier = spanStart < aEnd;
        const touchesLater = spanEnd > bStart;
        if (!touchesEarlier || !touchesLater) continue; // not straddling

        const contributingTurns = [i, i + 1];
        const key = `${threat.detectorId}:${threat.type}:${i}:${threat.location.offset}`;
        if (seen.has(key)) continue;
        seen.add(key);

        const { location: _drop, ...rest } = threat;
        crossTurnThreats.push({
          ...rest,
          contributingTurns,
          accumulatedConfidence: threat.confidence,
        });
      }
    }

    return { crossTurnThreats, windowChars };
  }

  /**
   * Aggregate per-turn results and cross-turn threats into a SessionScanResult.
   * Shared by the sync and async session paths. Cross-turn threats are passed
   * in by the (Phase 1/2) cross-turn detection; Phase 0 passes none.
   */
  private assembleSession(
    perTurn: ScanResult[],
    crossTurnThreats: CrossTurnThreat[],
    windowChars: number,
    durationMs: number
  ): SessionScanResult {
    const perTurnThreatCount = perTurn.reduce(
      (n, r) => n + r.threats.length,
      0
    );
    const severities = [
      ...perTurn.flatMap((r) => r.threats.map((t) => t.severity)),
      ...crossTurnThreats.map((t) => t.severity),
    ];
    const highestSeverity =
      severities.length > 0
        ? severities.reduce((hi, s) =>
            SEVERITY_ORDER[s] > SEVERITY_ORDER[hi] ? s : hi
          )
        : null;

    return {
      clean: perTurnThreatCount === 0 && crossTurnThreats.length === 0,
      turns: perTurn,
      crossTurnThreats,
      durationMs,
      stats: {
        turnsScanned: perTurn.length,
        windowChars,
        threatsFound: perTurnThreatCount + crossTurnThreats.length,
        crossTurnThreatsFound: crossTurnThreats.length,
        highestSeverity,
      },
    };
  }
}
