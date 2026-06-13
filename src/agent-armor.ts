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
import type { PatternDatabase } from './patterns/pattern-db';
import { DEFAULT_PATTERNS } from './patterns/default-patterns';
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
    decay: 0.5,
  },
};

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

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
  /** Guards the one-time "accumulation not yet implemented" warning. */
  private accumulationWarned = false;

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
   * Each turn is scanned independently (`turns`), and the recent turns are also
   * scanned for cross-turn split payloads (`crossTurnThreats`). Cross-turn
   * semantic accumulation is reserved for the ML classifier (see
   * `session.accumulation`) and is inactive here.
   */
  scanSession(turns: ConversationTurn[]): SessionScanResult {
    this.warnIfAccumulationRequested();
    const start = performance.now();
    const perTurn = turns.map((turn) => this.runScanPipeline(turn.content));
    const { crossTurnThreats, windowChars } = this.scanCrossTurn(turns);
    return this.assembleSession(
      perTurn,
      crossTurnThreats,
      windowChars,
      performance.now() - start
    );
  }

  /**
   * Scan a multi-turn conversation for agent traps (async).
   * Prefers scanAsync on detectors that support it (e.g. the ML classifier).
   */
  async scanSessionAsync(turns: ConversationTurn[]): Promise<SessionScanResult> {
    this.warnIfAccumulationRequested();
    const start = performance.now();
    const perTurn: ScanResult[] = [];
    for (const turn of turns) {
      perTurn.push(await this.runScanPipelineAsync(turn.content));
    }
    // Cross-turn split-payload detection is pattern-based (needs match offsets
    // to prove a span crosses a turn boundary); the sync window scan is reused.
    // ML threats carry no offsets and so do not produce cross-turn threats.
    const { crossTurnThreats, windowChars } = this.scanCrossTurn(turns);
    return this.assembleSession(
      perTurn,
      crossTurnThreats,
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
   * Cross-turn split-payload detection: catch payloads split across a boundary.
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
  /**
   * Cross-turn signal accumulation (session.accumulation) is not available in
   * the regex SDK — it is deferred to the ML classifier because a regex signal
   * cannot separate malicious standing-downplay rules from legitimate scripting
   * without unacceptable false positives. Warn once if a caller enables it, so
   * the option is never a silent no-op that fakes protection it does not give.
   */
  private warnIfAccumulationRequested(): void {
    if (this.config.session.accumulation && !this.accumulationWarned) {
      this.accumulationWarned = true;
      console.warn(
        '[AgentArmor] session.accumulation is not available in the regex SDK ' +
          '(deferred to the ML classifier); cross-turn signal accumulation is ' +
          'inactive. Split-payload detection is unaffected.'
      );
    }
  }

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
   * in by cross-turn detection; an empty list yields a per-turn-only result.
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
