import type {
  AgentArmorConfig,
  Detector,
  ScanResult,
  Severity,
  Strictness,
  Threat,
} from './types';
import {
  HiddenHTMLDetector,
  MetadataInjectionDetector,
  DynamicCloakingDetector,
  SyntacticMaskingDetector,
} from './detectors/content-injection';
import {
  JailbreakPatternDetector,
  ExfiltrationDetector,
  SubAgentSpawningDetector,
} from './detectors/behavioural-control';

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
};

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

export class AgentArmor {
  private config: Required<AgentArmorConfig>;
  private detectors: Detector[] = [];

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

    this.loadDetectors();
  }

  /**
   * Scan arbitrary content (HTML, markdown, plain text) for agent traps.
   * Use this for web-fetched content before it enters agent context.
   */
  scanContent(content: string): ScanResult {
    return this.runScanPipeline(content);
  }

  /**
   * Scan retrieved RAG chunks before prompt assembly.
   * Returns per-chunk results so you can filter poisoned documents.
   */
  scanRAGChunks(chunks: string[]): ScanResult[] {
    return chunks.map((chunk) => this.runScanPipeline(chunk));
  }

  /**
   * Scan agent output before it reaches the user.
   * Detects exfiltration attempts and social engineering patterns.
   */
  scanOutput(output: string): ScanResult {
    return this.runScanPipeline(output);
  }

  /**
   * Get the current strictness level.
   */
  get strictness(): Strictness {
    return this.config.strictness;
  }

  // ---------------------------------------------------------------------------
  // Internal
  // ---------------------------------------------------------------------------

  private loadDetectors(): void {
    const ci = this.config.contentInjection;
    const bc = this.config.behaviouralControl;

    // Content Injection detectors
    if (ci.hiddenHTML) this.detectors.push(new HiddenHTMLDetector());
    if (ci.metadataInjection)
      this.detectors.push(new MetadataInjectionDetector());
    if (ci.dynamicCloaking)
      this.detectors.push(new DynamicCloakingDetector());
    if (ci.syntacticMasking)
      this.detectors.push(new SyntacticMaskingDetector());

    // Behavioural Control detectors
    if (bc.jailbreakPatterns)
      this.detectors.push(new JailbreakPatternDetector());
    if (bc.exfiltrationURLs) this.detectors.push(new ExfiltrationDetector());
    if (bc.privilegeEscalation)
      this.detectors.push(new SubAgentSpawningDetector());

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

    // Sort by severity descending, then confidence descending
    allThreats.sort((a, b) => {
      const sevDiff = SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity];
      if (sevDiff !== 0) return sevDiff;
      return b.confidence - a.confidence;
    });

    // Sanitize content by running all detectors' sanitize methods
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
