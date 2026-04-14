import type {
  AgentArmorConfig,
  Detector,
  MLConfig,
  ScanResult,
  Severity,
  Strictness,
  Threat,
  TrapCategory,
  TrapType,
} from './types';
import type { PatternDatabase } from './patterns/pattern-db';
import { DEFAULT_PATTERNS } from './patterns/default-patterns';
import { PatternDetector } from './detectors/pattern-detector';

const DEFAULT_CONFIG: Required<AgentArmorConfig> = {
  strictness: 'balanced',
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
    }

    // Custom detectors
    this.detectors.push(...this.config.customDetectors);
  }

  private runScanPipeline(content: string): ScanResult {
    const start = performance.now();
    const allThreats: Threat[] = [];

    for (const detector of this.detectors) {
      try {
        const result = detector.scan(content, {
          strictness: this.config.strictness,
        });
        allThreats.push(...result.threats);
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

    for (const detector of this.detectors) {
      try {
        if ('scanAsync' in detector && typeof detector.scanAsync === 'function') {
          const result = await detector.scanAsync(content, {
            strictness: this.config.strictness,
          });
          allThreats.push(...result.threats);
        } else {
          const result = detector.scan(content, {
            strictness: this.config.strictness,
          });
          allThreats.push(...result.threats);
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
}
