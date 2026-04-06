import { LABELS } from './constants';
import { Tokenizer } from './tokenizer';
import type { ModelArtifacts } from './model-manager';

// Inline types matching @stylusnexus/agentarmor's Detector interface
// These will be compatible at runtime via structural typing
interface DetectorOptions {
  strictness?: 'permissive' | 'balanced' | 'strict';
}

interface DetectorResult {
  threats: Threat[];
}

interface Threat {
  category: string;
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  confidence: number;
  description: string;
  evidence: string;
  location?: { offset: number; length: number };
  detectorId: string;
  source: 'pattern' | 'ml' | 'custom';
}

interface Detector {
  id: string;
  name: string;
  category: string;
  scan(content: string, options?: DetectorOptions): DetectorResult;
  scanAsync?(content: string, options?: DetectorOptions): Promise<DetectorResult>;
  sanitize(content: string, threats: Threat[]): string;
}

// ONNX Runtime types
interface OrtSession {
  run(feeds: Record<string, any>): Promise<Record<string, any>>;
}

interface OrtModule {
  InferenceSession: { create(path: string): Promise<OrtSession> };
  Tensor: new (type: string, data: any, dims: number[]) => any;
}

const THRESHOLDS: Record<string, number> = {
  strict: 0.3,
  balanced: 0.5,
  permissive: 0.7,
};

const LABEL_TO_CATEGORY: Record<string, string> = {
  'hidden-html': 'content-injection',
  'metadata-injection': 'content-injection',
  'dynamic-cloaking': 'content-injection',
  'syntactic-masking': 'content-injection',
  'embedded-jailbreak': 'behavioural-control',
  'data-exfiltration': 'behavioural-control',
  'sub-agent-spawning': 'behavioural-control',
  'benign': 'content-injection',
};

export class MLDetector implements Detector {
  readonly id = 'ml-classifier';
  readonly name = 'ML Classifier (DeBERTa-v3-small)';
  readonly category = 'content-injection';

  private session: OrtSession;
  private tokenizer: Tokenizer;
  private ort: OrtModule;

  private constructor(session: OrtSession, tokenizer: Tokenizer, ort: OrtModule) {
    this.session = session;
    this.tokenizer = tokenizer;
    this.ort = ort;
  }

  static async create(artifacts: ModelArtifacts): Promise<MLDetector> {
    const ort = await import('onnxruntime-node') as unknown as OrtModule;
    const session = await ort.InferenceSession.create(artifacts.modelPath);
    const tokenizer = await Tokenizer.fromFile(artifacts.tokenizerPath);
    return new MLDetector(session, tokenizer, ort);
  }

  // Sync scan returns empty — ML inference is async only
  scan(_content: string, _options?: DetectorOptions): DetectorResult {
    return { threats: [] };
  }

  // Async scan runs ONNX inference
  async scanAsync(content: string, options?: DetectorOptions): Promise<DetectorResult> {
    const strictness = options?.strictness ?? 'balanced';
    const threshold = THRESHOLDS[strictness] ?? THRESHOLDS.balanced;

    const { inputIds, attentionMask } = this.tokenizer.encode(content, 512);

    const feeds: Record<string, any> = {
      input_ids: new this.ort.Tensor('int64', inputIds, [1, 512]),
      attention_mask: new this.ort.Tensor('int64', attentionMask, [1, 512]),
    };

    const results = await this.session.run(feeds);
    const logits = results.logits?.data as Float32Array;
    if (!logits) return { threats: [] };

    const threats: Threat[] = [];
    for (let i = 0; i < LABELS.length; i++) {
      const label = LABELS[i];
      if (label === 'benign') continue;

      const prob = 1 / (1 + Math.exp(-logits[i]));
      if (prob >= threshold) {
        threats.push({
          category: LABEL_TO_CATEGORY[label] ?? 'content-injection',
          type: label,
          severity: prob >= 0.9 ? 'critical' : prob >= 0.7 ? 'high' : prob >= 0.5 ? 'medium' : 'low',
          confidence: prob,
          description: `ML classifier detected ${label} (confidence: ${(prob * 100).toFixed(1)}%)`,
          evidence: content.slice(0, 200),
          detectorId: 'ml-classifier',
          source: 'ml',
        });
      }
    }

    return { threats };
  }

  // ML detector doesn't modify content — pattern detectors handle sanitization
  sanitize(content: string, _threats: Threat[]): string {
    return content;
  }
}
