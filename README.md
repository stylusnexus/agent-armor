# Agent Armor

[![npm version](https://img.shields.io/npm/v/@stylusnexus/agentarmor.svg)](https://www.npmjs.com/package/@stylusnexus/agentarmor)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**[agentarmor.dev](https://agentarmor.dev)** | **[npm](https://www.npmjs.com/package/@stylusnexus/agentarmor)** | **[GitHub](https://github.com/stylusnexus/agent-armor)**

Open-source security framework for AI agents. Detects and defends against **AI Agent Traps** — adversarial content designed to manipulate, deceive, or exploit autonomous AI agents.

Built on the taxonomy from [AI Agent Traps](https://arxiv.org/abs/2506.01559) (Franklin et al., Google DeepMind, 2025).

## The Problem

As AI agents browse the web, process documents, and interact with external data, they encounter a new attack surface: **the information environment itself**. Malicious content can be engineered to hijack agent behavior through hidden instructions, poisoned knowledge bases, embedded jailbreaks, and more — all invisible to the human overseer.

Agent Armor provides a defense-in-depth pipeline that scans content at every stage of the agent lifecycle.

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

## Quick Start

```bash
npm install @stylusnexus/agentarmor
```

```typescript
import { AgentArmor } from '@stylusnexus/agentarmor';

const armor = new AgentArmor();

// Scan web content before it enters your agent's context
const result = armor.scanContent(htmlString);

if (!result.clean) {
  console.warn('Threats detected:', result.threats);
  // Use result.sanitized for cleaned content
}

// Scan retrieved RAG chunks before prompt assembly
const ragResults = armor.scanRAGChunks(retrievedDocuments);
const safeChunks = ragResults
  .filter(r => r.clean)
  .map((r, i) => retrievedDocuments[i]);

// Scan agent output before it reaches the user
const outputResult = armor.scanOutput(agentResponse);
```

## Configuration

```typescript
const armor = new AgentArmor({
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
}
```

## Updatable Pattern Database

Patterns are data-driven, not hardcoded. Update without upgrading the package:

```typescript
// Fetch latest patterns from agentarmor.dev (coming soon)
const latestPatterns = await AgentArmor.fetchLatestPatterns();
armor.loadPatterns(latestPatterns);

// Or load custom patterns
armor.loadPatterns(myCustomPatterns);

// Check current pattern version
console.log(armor.patternVersion); // '0.2.0'
```

## Custom Detectors

Extend Agent Armor with your own detectors:

```typescript
import { AgentArmor, type Detector } from '@stylusnexus/agentarmor';

const myDetector: Detector = {
  id: 'my-custom-detector',
  name: 'My Custom Detector',
  category: 'content-injection',
  scan: (content, options) => {
    // Your detection logic here
    return { threats: [] };
  },
  sanitize: (content, threats) => content,
};

const armor = new AgentArmor({
  customDetectors: [myDetector],
});
```

## Architecture

Agent Armor operates as a middleware pipeline with three interception points:

```
External Content --> [Pre-Ingestion Scanner] --> Agent Context
                                                      |
                    [Post-Retrieval Scanner] <-- RAG/Memory Store
                                                      |
                    [Pre-Execution Scanner]  --> Agent Output --> User
```

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

## Framework Agnostic

Agent Armor works with any LLM agent framework:

- **LangChain / LangGraph** — Use as a preprocessing step in your chain
- **Claude Code / Anthropic SDK** — Drop into tool result processing
- **OpenAI Agents SDK** — Wrap tool outputs before context assembly
- **AutoGen / CrewAI** — Add as an inter-agent message filter
- **Custom agents** — Call directly in your pipeline

## Performance

All detectors are regex-based with zero dependencies. Typical scan times:

- Small content (<1KB): <1ms
- Medium content (~10KB): ~2-5ms
- Large content (~100KB): ~10-20ms

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
