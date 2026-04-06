# Agent Armor

[![npm version](https://img.shields.io/npm/v/@stylusnexus/agentarmor.svg)](https://www.npmjs.com/package/@stylusnexus/agentarmor)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**[agentarmor.dev](https://agentarmor.dev)** | **[npm](https://www.npmjs.com/package/@stylusnexus/agentarmor)** | **[GitHub](https://github.com/stylusnexus/agent-armor)**

Open-source security framework for AI agents. Detects and defends against **AI Agent Traps** — adversarial content designed to manipulate, deceive, or exploit autonomous AI agents.

Built on the taxonomy from [AI Agent Traps](https://arxiv.org/abs/2506.01559) (Franklin et al., Google DeepMind, 2025).

## The Problem

As AI agents browse the web, process documents, and interact with external data, they encounter a new attack surface: **the information environment itself**. Malicious content can be engineered to hijack agent behavior through hidden instructions, poisoned knowledge bases, embedded jailbreaks, and more — all invisible to the human overseer.

Agent Armor provides a defense-in-depth pipeline that scans content at every stage of the agent lifecycle.

## Quick Start

### Regex-only (synchronous)

Zero dependencies, sub-millisecond scans:

```typescript
import { AgentArmor } from '@stylusnexus/agentarmor';

const armor = AgentArmor.regexOnly();

const result = armor.scanSync(htmlString);

if (!result.clean) {
  console.warn('Threats detected:', result.threats);
  // Use result.sanitized for cleaned content
}
```

### With ML classifier (asynchronous)

For deeper detection using an ONNX-based classifier:

```typescript
import { AgentArmor } from '@stylusnexus/agentarmor';

const armor = await AgentArmor.create({
  ml: { enabled: true },
});

const result = await armor.scan(htmlString);

if (!result.clean) {
  console.warn('Threats detected:', result.threats);
}
```

## Install

Core package (regex-based detection, zero dependencies):

```bash
npm install @stylusnexus/agentarmor
```

Optional ML classifier for deeper detection:

```bash
npm install @stylusnexus/agentarmor-ml
```

## Evaluation Results

Tested against 42 curated samples (28 adversarial, 14 benign) covering all 7 detector categories:

| Strictness | Detection Rate | False Positive Rate |
|---|---|---|
| Permissive | 96.4% | 0.0% |
| **Balanced** | **100%** | **0.0%** |
| Strict | 100% | 0.0% |

Run the evaluation yourself: `npx tsx scripts/eval/run-eval.ts`

## Attack Categories Covered

| Category | Target | Status | What It Detects |
|---|---|---|---|
| **Content Injection** | Perception | Shipped | Hidden HTML/CSS instructions, metadata injection, dynamic cloaking artifacts, syntactic masking |
| **Behavioural Control** | Action | Shipped | Embedded jailbreak sequences, data exfiltration patterns, sub-agent spawning traps |
| **Cognitive State** | Memory | Planned | RAG knowledge poisoning, latent memory poisoning, contextual learning manipulation |
| **Semantic Manipulation** | Reasoning | Planned | Biased framing/priming, oversight evasion, persona hyperstition |
| **Systemic** | Multi-Agent | Planned | Congestion traps, interdependence cascades, tacit collusion, compositional fragments, sybil attacks |
| **Human-in-the-Loop** | Overseer | Planned | Approval fatigue induction, social engineering via compromised agent |

## Configuration

```typescript
const armor = await AgentArmor.create({
  // Enable/disable specific detectors
  contentInjection: {
    hiddenHTML: true,        // CSS display:none, off-screen positioning
    metadataInjection: true, // aria-label, HTML comments with instructions
    dynamicCloaking: true,   // Bot detection scripts
    syntacticMasking: true,  // Markdown/LaTeX payload hiding
  },
  behaviouralControl: {
    jailbreakPatterns: true, // Known jailbreak sequence detection
    exfiltrationURLs: true,  // Data exfiltration patterns
    privilegeEscalation: true, // Sub-agent spawning triggers
  },
  // Strictness affects confidence thresholds
  // 'permissive' = fewer alerts, higher confidence required
  // 'balanced'   = recommended default
  // 'strict'     = more alerts, catches subtle attacks
  strictness: 'balanced',

  // ML classifier (requires @stylusnexus/agentarmor-ml)
  ml: {
    enabled: true,
    // Behavior when ML model is unavailable:
    // 'throw' (default) | 'warn-and-skip' | 'silent-skip'
    onUnavailable: 'warn-and-skip',
  },
});
```

For sync-only usage without ML, use `AgentArmor.regexOnly()` which accepts the same options minus `ml`:

```typescript
const armor = AgentArmor.regexOnly({
  strictness: 'strict',
  contentInjection: { hiddenHTML: true, metadataInjection: true },
});
```

## Scan Results

Every scan returns a `ScanResult` with full threat details:

```typescript
interface ScanResult {
  clean: boolean;          // true if no threats found
  threats: Threat[];       // sorted by severity, then confidence
  sanitized: string;       // content with threats neutralized
  durationMs: number;      // scan time in milliseconds
  stats: {
    detectorsRun: number;
    threatsFound: number;
    highestSeverity: 'low' | 'medium' | 'high' | 'critical' | null;
  };
}

interface Threat {
  category: TrapCategory;  // e.g. 'content-injection'
  type: TrapType;          // e.g. 'hidden-html'
  severity: Severity;      // 'low' | 'medium' | 'high' | 'critical'
  confidence: number;      // 0-1
  description: string;     // human-readable explanation
  evidence: string;        // the offending content (truncated)
  location?: { offset: number; length: number };
  detectorId: string;
  source: 'pattern' | 'ml' | 'custom';  // how the threat was detected
}
```

The `source` field indicates which detection method found the threat:
- `'pattern'` — matched by a regex pattern from the built-in pattern database
- `'ml'` — flagged by the ML classifier
- `'custom'` — found by a user-provided custom detector

## ML Classifier

The optional `@stylusnexus/agentarmor-ml` package adds an ONNX-based classifier that catches threats regex patterns might miss. It downloads the model on first use and caches it locally.

```typescript
const armor = await AgentArmor.create({
  ml: {
    enabled: true,
    // Optional: point to a local model directory
    modelDir: './models/agentarmor',
    // Optional: configure download behavior
    download: {
      timeoutMs: 120_000,
      retries: 2,
      onProgress: (received, total) => {
        console.log(`Downloading model: ${Math.round(received / total * 100)}%`);
      },
    },
    // Optional: gracefully degrade if model is unavailable
    onUnavailable: 'warn-and-skip',
  },
});
```

When ML is enabled, calling `await armor.scan(content)` runs both regex and ML detectors. The ML classifier's threats have `source: 'ml'` in the result, making it easy to distinguish them from pattern-based detections.

If the ML package is not installed or the model is unavailable, behavior depends on the `onUnavailable` setting: `'throw'` (default), `'warn-and-skip'`, or `'silent-skip'`.

## Architecture

Agent Armor operates as a middleware pipeline with three interception points:

```
External Content --> [Pre-Ingestion Scanner] --> Agent Context
                                                      |
                    [Post-Retrieval Scanner] <-- RAG/Memory Store
                                                      |
                    [Pre-Execution Scanner]  --> Agent Output --> User
```

Each interception point has both sync and async methods:

| Stage | Sync | Async |
|---|---|---|
| Pre-ingestion | `scanSync(content)` | `await scan(content)` |
| Post-retrieval | `scanRAGChunksSync(chunks)` | `await scanRAGChunks(chunks)` |
| Pre-execution | `scanOutputSync(output)` | `await scanOutput(output)` |

## Detectors

### Content Injection (Shipped)

- **HiddenHTMLDetector** — Finds instructions hidden via CSS (`display:none`, `visibility:hidden`, off-screen positioning)
- **MetadataInjectionDetector** — Scans HTML comments, `aria-label`, `alt` attributes, `meta` tags for injected instructions
- **DynamicCloakingDetector** — Detects JavaScript patterns that serve different content to agents vs humans
- **SyntacticMaskingDetector** — Identifies payloads hidden in Markdown link text, LaTeX commands, zero-width characters, or bidi overrides

### Behavioural Control (Shipped)

- **JailbreakPatternDetector** — Pattern-matches against known jailbreak templates (DAN, role-play bypasses, educational framing exploits, developer mode claims)
- **ExfiltrationDetector** — Flags instructions that attempt to locate, encode, and transmit context data to external endpoints
- **SubAgentSpawningDetector** — Detects instructions that try to instantiate new agents, escalate tool permissions, or inject pipeline steps

## Performance

The core regex detectors have zero dependencies and run with sub-millisecond latency. When the ML classifier is enabled, scan times increase but remain practical for real-time use:

- **Regex only:** <1ms for small content, ~2-5ms for 10KB, ~10-20ms for 100KB
- **With ML:** ~50-200ms depending on content length and hardware

Use `scanSync()` for latency-critical paths and `await scan()` when ML detection is needed.

## Custom Detectors

Extend Agent Armor with your own detectors:

```typescript
import { AgentArmor, type Detector } from '@stylusnexus/agentarmor';

const myDetector: Detector = {
  id: 'my-custom-detector',
  name: 'My Custom Detector',
  category: 'content-injection',
  scan: (content, options) => {
    // Your sync detection logic
    return {
      threats: [
        // Each threat must include the `source` field
        {
          category: 'content-injection',
          type: 'hidden-html',
          severity: 'high',
          confidence: 0.95,
          description: 'Found suspicious pattern',
          evidence: content.slice(0, 100),
          detectorId: 'my-custom-detector',
          source: 'custom',
        },
      ],
    };
  },
  // Optional: async detection (used by `scan()`, `scanRAGChunks()`, `scanOutput()`)
  scanAsync: async (content, options) => {
    // Your async detection logic (e.g. call an external API)
    return { threats: [] };
  },
  sanitize: (content, threats) => content,
};

const armor = AgentArmor.regexOnly({
  customDetectors: [myDetector],
});
```

## Updatable Pattern Database

Patterns are data-driven, not hardcoded. Update without upgrading the package:

```typescript
// Fetch latest patterns from your pattern server
const latestPatterns = await AgentArmor.fetchLatestPatterns('https://your-server.com/patterns.json');
armor.loadPatterns(latestPatterns);

// Or load custom patterns directly
armor.loadPatterns(myCustomPatterns);

// Check current pattern version
console.log(armor.patternVersion); // '0.2.0'
```

## Framework Agnostic

Agent Armor works with any LLM agent framework:

- **LangChain / LangGraph** — Use as a preprocessing step in your chain
- **Claude Code / Anthropic SDK** — Drop into tool result processing
- **OpenAI Agents SDK** — Wrap tool outputs before context assembly
- **AutoGen / CrewAI** — Add as an inter-agent message filter
- **Custom agents** — Call directly in your pipeline

## Contributing

We welcome contributions, especially:
- New adversarial samples for the evaluation suite (`scripts/eval/samples.ts`)
- New detection patterns for the pattern database (`src/patterns/default-patterns.ts`)
- Custom detectors for novel attack vectors

## Research Foundation

This project implements defenses based on the systematic framework proposed in:

> Franklin, M., Tomasev, N., Jacobs, J., Leibo, J.Z., & Osindero, S. (2025). *AI Agent Traps*. Google DeepMind.

## License

MIT
