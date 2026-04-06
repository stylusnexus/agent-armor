import type {
  AgentArmorConfig,
  Detector,
  MLConfig,
  ScanResult,
  Severity,
  Strictness,
  Threat,
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
  configGroup: 'contentInjection' | 'behaviouralControl';
  configKey: string;
  patternDbKey: string;
  id: string;
  name: string;
  category: 'content-injection' | 'behavioural-control';
  trapType: string;
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
    if (config?.ml) {
      await instance.initML(config.ml);
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
  }

  /**
   * Get the current pattern database version.
   */
  get patternVersion(): string {
    return this.patternDb.version;
  }

  /**
   * Fetch the latest patterns from a remote URL.
   * Defaults to the agent-armor GitHub releases.
   */
  static async fetchLatestPatterns(
    url?: string
  ): Promise<PatternDatabase> {
    const fetchUrl =
      url ?? 'https://api.agentarmor.dev/patterns/latest';
    const response = await fetch(fetchUrl);
    if (!response.ok) {
      throw new Error(
        `Failed to fetch patterns: ${response.status} ${response.statusText}`
      );
    }
    return (await response.json()) as PatternDatabase;
  }

  /**
   * Scan arbitrary content for agent traps.
   */
  scanContent(content: string): ScanResult {
    return this.runScanPipeline(content);
  }

  /**
   * Scan retrieved RAG chunks before prompt assembly.
   */
  scanRAGChunks(chunks: string[]): ScanResult[] {
    return chunks.map((chunk) => this.runScanPipeline(chunk));
  }

  /**
   * Scan agent output before it reaches the user.
   */
  scanOutput(output: string): ScanResult {
    return this.runScanPipeline(output);
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
          trapType: reg.trapType as any,
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
      const result = detector.scan(content, {
        strictness: this.config.strictness,
      });
      allThreats.push(...result.threats);
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
