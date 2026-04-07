# Agent Armor

[![npm version](https://img.shields.io/npm/v/@stylusnexus/agentarmor.svg)](https://www.npmjs.com/package/@stylusnexus/agentarmor)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**[agentarmor.dev](https://agentarmor.dev)** | **[npm](https://www.npmjs.com/package/@stylusnexus/agentarmor)** | **[GitHub](https://github.com/stylusnexus/agent-armor)**

Open-source security framework for AI agents. Detects and defends against **AI Agent Traps** — adversarial content designed to manipulate, deceive, or exploit autonomous AI agents.

Built on the taxonomy from [AI Agent Traps](https://papers.ssrn.com/sol3/papers.cfm?abstract_id=6372438) (Franklin et al., Google DeepMind, 2026).

## Why This Matters

AI agents ingest content they didn't generate: web pages, RAG chunks, tool outputs, database results. Any of that content can contain instructions designed to hijack the agent's behavior, and the agent can't tell the difference between data and directives.

This isn't theoretical. It's happening now:

- **[Slack AI data exfiltration](https://www.lakera.ai/blog/indirect-prompt-injection)** (2024): Poisoned messages in Slack channels caused the AI assistant to extract and leak data from private channels through tool calls.
- **[EchoLeak / Microsoft 365 Copilot](https://www.exploitone.com/cyber-security/the-invisible-breach-how-ai-agents-became-the-most-dangerous-attack-surface-of-2025-2026/)**: A zero-click attack where a single email with hidden instructions made Copilot exfiltrate data from OneDrive, SharePoint, and Teams, routed through trusted Microsoft URLs so it looked like internal links.
- **[Devin AI pentest](https://adversa.ai/blog/adversa-ai-unveils-explosive-2025-ai-security-incidents-report-revealing-how-generative-and-agentic-ai-are-already-under-attack/)** (2025): A $500 security test found the coding agent completely defenseless against prompt injection. It exposed ports, leaked access tokens, and installed command-and-control malware.
- **[SSH key exfiltration via GPT-4o](https://swarmsignal.net/ai-agent-security-2026/)** (Jan 2026): A single poisoned email coerced GPT-4o into executing Python that exfiltrated SSH keys in 80% of trials.
- **[CamoLeak / GitHub Copilot](https://www.legitsecurity.com/blog/camoleak)** (2025, CVE-2025-59145): Hidden markdown comments in PRs caused Copilot Chat to exfiltrate secrets via image proxy ordering. No network traffic from the user's browser. CVSS 9.6.
- **[Clinejection](https://adnanthekhan.com/posts/clinejection/)** (Jan-Feb 2026): A single GitHub issue title with prompt injection hijacked Cline's AI triage bot, leading to unauthorized `cline@2.3.0` on npm (4,000 downloads in 8 hours).
- **[MCP tool poisoning](https://invariantlabs.ai/blog/whatsapp-mcp-exploited)** (2025): MCP servers silently changed tool descriptions after approval, rerouting WhatsApp messages and exfiltrating data. Invariant Labs found 5.5% of MCP servers exhibit tool poisoning.

Google DeepMind's [AI Agent Traps](https://papers.ssrn.com/sol3/papers.cfm?abstract_id=6372438) taxonomy (Franklin et al., 2026) catalogs 14 attack types across 6 categories. [OpenAI has stated](https://techcrunch.com/2025/12/22/openai-says-ai-browsers-may-always-be-vulnerable-to-prompt-injection-attacks/) that AI browsers "may always be vulnerable" to prompt injection.

Agent Armor scans content at every stage of the agent lifecycle: before ingestion, after retrieval, and before the agent's output reaches the user. Input validation *and* output validation in one pipeline.

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

## Testing & Validation

### Eval Suite

86 curated samples (59 adversarial, 27 benign) covering all 10 shipped detector types across 4 attack categories:

| Strictness | Detection Rate (regex) | False Positive Rate |
|---|---|---|
| Permissive | 79.7% | 0.0% |
| **Balanced** | **89.8%** | **0.0%** |
| Strict | 89.8% | 0.0% |

The eval suite includes 10 adversarial samples drawn from real-world incidents (2025-2026): MCP tool poisoning, RAG vector DB saturation, covert exfiltration via image proxies, supply chain prompt injection, memory poisoning, and HITL dialog forgery. Regex catches 5 of these; the remaining 5 (pure social engineering and context-dependent attacks) measure the gap that the [ML classifier](#ml-classifier-optional) closes. On the original 49 adversarial samples, regex detection is 100% at balanced strictness.

Sources: [WASP benchmark](https://arxiv.org/abs/2312.02119) (Evtimov et al.), [HackAPrompt](https://arxiv.org/abs/2311.16119) (Schulhoff et al., 2023), [Greshake et al. (2023)](https://arxiv.org/abs/2302.12173), the [DeepMind paper](https://papers.ssrn.com/sol3/papers.cfm?abstract_id=6372438), and incident reports from [Invariant Labs](https://invariantlabs.ai/blog), [Unit 42](https://unit42.paloaltonetworks.com), [Snyk Labs](https://labs.snyk.io), [Legit Security](https://www.legitsecurity.com/blog/camoleak), and [Socket Research](https://socket.dev/blog). Benign samples include security blog posts, legitimate HTML, CI/CD docs, MCP tool descriptions, agent interaction logs, and procurement policy emails.

Run it yourself: `npx tsx scripts/eval/run-eval.ts`

### Real-World Attack Validation

A separate validation suite (`examples/real-world-validation.ts`) tests against 24 inlined samples drawn directly from published security research:

| Source | Attack Type | Samples |
|---|---|---|
| Unit 42 (Palo Alto Networks), 2025 | Hidden CSS/HTML injection | 6 |
| Greshake et al., 2023 | Indirect prompt injection | 4 |
| JailbreakBench / HackAPrompt | Jailbreak patterns | 5 |
| Embrace The Red (J. Rehberger) | Data exfiltration via agents | 4 |
| Benign false-positive controls | Security docs, normal HTML/email | 5 |

Result: **100% detection, 0% false positives** at balanced strictness. All samples are inlined for offline reproducibility, no network required.

Run it: `npx tsx examples/real-world-validation.ts`

## Attack Categories Covered

| Category | Target | Status | What It Detects |
|---|---|---|---|
| **Content Injection** | Perception | Shipped | Hidden HTML/CSS instructions, metadata injection, dynamic cloaking artifacts, syntactic masking |
| **Behavioural Control** | Action | Shipped | Embedded jailbreak sequences, data exfiltration patterns, sub-agent spawning traps |
| **Cognitive State** | Memory | Shipped | RAG knowledge poisoning, latent memory poisoning, contextual learning manipulation |
| **Semantic Manipulation** | Reasoning | Shipped | Biased framing/priming, oversight evasion, persona hyperstition |
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
  // 'permissive' = only high-confidence threats (87.8% detection)
  // 'balanced'   = recommended default (100% detection, 0% FP)
  // 'strict'     = maximum coverage, catches subtle attacks
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

## Strictness Levels

Strictness controls the confidence threshold for reporting threats. Every pattern in the detection database has a confidence score (0-1). Strictness determines which patterns are sensitive enough to report.

| Level | Confidence Threshold | Use When |
|---|---|---|
| `permissive` | 0.7+ only | You want minimal noise. Only high-confidence, unambiguous threats are reported. Some subtle attacks will be missed. Good for high-volume pipelines where false positives are expensive. |
| `balanced` | 0.5+ | **Recommended default.** Catches all well-formed attacks while maintaining 0% false positives on our eval suite. Good for most production agents. |
| `strict` | 0.3+ | You want maximum coverage. Reports lower-confidence signals that may need human review. Best for security-sensitive environments or when scanning untrusted external content. |

At `permissive`, 6 of 49 adversarial samples in our eval suite go undetected because their pattern confidence falls below the 0.7 threshold. These are mostly subtle semantic manipulation and cognitive state attacks (biased framing, oversight evasion, persona manipulation). At `balanced` and `strict`, all 49 are caught with 0% false positives.

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

## Examples

The `examples/` directory has ready-to-run integration examples:

| Example | Audience | What it shows |
|---|---|---|
| `customer-facing-agent.ts` | SMB / Startup | Protect a support chatbot: scan knowledge base, customer messages, and agent output |
| `audit-logging.ts` | Enterprise | Policy enforcement + structured audit log for compliance (SOC2, ISO 27001) |
| `tool-output-guard.ts` | Developer | Guard every tool call in a custom agent loop (web, DB, file, API) |
| `rag-pipeline.ts` | Developer | Filter poisoned RAG chunks before LLM context assembly |
| `express-middleware.ts` | Developer | Express middleware that scans and sanitizes requests |
| `web-content-scanner.ts` | Developer | Scan raw HTML from web fetches in strict mode |
| `ml-classifier.ts` | Developer | Async pipeline with ML classifier enabled |
| `custom-detector.ts` | Developer | Implement and register a custom `Detector` |
| `real-world-validation.ts` | Security | Validate against real-world attack samples from published research |

Run any example:

```bash
npx tsx examples/rag-pipeline.ts
```

## Roadmap & Research Opportunities

Agent Armor covers 4 of the 6 attack categories in the DeepMind taxonomy. Here's what's shipped, what's next, and where the open questions are.

### Shipped

- **Content Injection** (4 detectors) and **Behavioural Control** (3 detectors) since v0.1.0
- **Cognitive State** (3 detectors) and **Semantic Manipulation** (3 detectors) since v0.2.0
- ML classifier (DeBERTa-v3-small, ONNX) as optional companion package
- Pattern database v0.4.0 with 71 pattern entries

### In Progress

- **Expanded eval dataset.** 71 samples is a start, not a finish. Integrating larger public datasets ([deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections) at 662 samples, [Giskard-AI](https://huggingface.co/datasets/Giskard-AI/prompt-injections)) to stress-test detection and false positive rates at scale.
- **Honeypot/canary system.** Behavioral baseline approach for detecting novel attacks that bypass pattern matching. Measures response distribution drift rather than relying on known signatures.
- **Pattern update API.** Continuous pattern improvements delivered without requiring an npm upgrade.

### Not Yet Covered (P2)

These are the remaining 2 categories from the taxonomy. They're harder problems with less established detection approaches:

- **Systemic attacks** (multi-agent): congestion traps, interdependence cascades, tacit collusion, compositional fragment attacks, sybil attacks. These target multi-agent architectures and require detection approaches that reason about agent-to-agent interactions, not just content.
- **Human-in-the-loop attacks**: approval fatigue induction, social engineering via compromised agent. These exploit the human overseer rather than the agent itself. Detection likely requires behavioral analysis over time rather than content scanning.

### Open Research Questions

If you're a researcher or practitioner thinking about these problems, we'd value your perspective:

- **Hierarchical vs. flat classification.** The ML classifier uses multi-label flat classification (14 outputs). Would a hierarchical approach (category first, then type) better reflect the taxonomy structure and improve accuracy on underrepresented categories?
- **Semantic manipulation detection.** Biased framing and persona hyperstition are inherently subtle. Regex catches the obvious cases, but sophisticated semantic attacks may require embedding-level analysis or chain-of-thought reasoning about intent. What's the right detection architecture here?
- **Cross-session attack detection.** Latent memory poisoning and contextual learning traps accumulate over multiple interactions. The current scan-per-input approach can't detect gradual drift. What does a stateful detection layer look like?
- **Adversarial robustness of the detector itself.** If an attacker knows the pattern database, they can craft bypasses. How do we make the detection layer robust to adversarial evasion without creating an arms race?

### Staying Updated

- **Pattern database** is versioned and updatable independently of the npm package via `AgentArmor.fetchLatestPatterns()`
- **ML model** is retrained periodically with new attack samples and pushed to [HuggingFace](https://huggingface.co/stylusnexus/agent-armor-classifier)
- **GitHub releases** track all changes with a [CHANGELOG](CHANGELOG.md)
- **Security issues** can be reported via [SECURITY.md](SECURITY.md)

## FAQ

### Who is this for?

Agent Armor protects **agents you build and control**. If you're writing agent code using Claude API, Azure OpenAI, LangChain, CrewAI, AutoGen, or any framework where you own the data pipeline, this is for you.

| You are... | Agent Armor helps you... |
|---|---|
| **A developer** building an AI agent that calls tools, browses the web, or uses RAG | Scan every piece of external content before it enters your agent's context |
| **A startup/SMB** with a customer-facing AI chatbot or support agent | Protect your knowledge base from poisoning and your agent's output from manipulation |
| **An enterprise team** building custom AI tooling on top of LLM APIs | Add audit logging, policy enforcement, and compliance evidence to your agent pipeline |

### Can this protect our Microsoft 365 Copilot / Claude.ai / ChatGPT deployment?

Not directly. Those are closed pipelines where the vendor controls the scanning. Agent Armor can't insert itself between Copilot and the content it reads from SharePoint or Teams. If you're using a hosted AI product as-is, the vendor is responsible for security on their end.

Where it *does* fit: if your team is building custom agents *using* the Claude API, Azure OpenAI, or other LLM APIs, you control the pipeline, and Agent Armor is the scanning layer for it.

### Isn't this just prompt injection detection?

Prompt injection is one attack type out of the 10 we cover (detected by 13 detectors). Prompt injection targets chatbots within a single conversation. Agent traps target autonomous agents with tool access, persistent memory, and sub-agent spawning. Different attack surface, different blast radius.

The full taxonomy includes content injection, behavioral control, cognitive state manipulation (RAG/memory poisoning), and semantic manipulation (biased framing, persona shifts). These are distinct attack categories with different detection approaches.

### Can a determined attacker bypass this?

Yes. A sophisticated adversary with knowledge of the pattern database can craft content that evades regex detection. The ML classifier raises the bar significantly, but no detection system is foolproof.

Agent Armor is defense-in-depth. It raises the cost of attack and catches the broad majority of real-world attacks. Think of it as input validation for your agent pipeline, grounded in a real taxonomy rather than guesswork.

### What about false positives?

False positives are the hardest problem in this space. Naive regex on security-adjacent vocabulary (phrases like "ignore previous instructions," "system prompt," "act as") generates enormous noise on legitimate developer content, documentation, and security research.

The solution is a two-pass detection pipeline: structural pattern match first, then an instruction signal context check. Patterns that would cause noise have a `requireInstructions` flag that prevents them from firing without that second signal. On our eval suite of 71 samples (including security blog posts, AI safety textbooks, and CI/CD documentation as benign controls), the false positive rate is 0%.

### How much latency does this add?

The regex-based core runs in sub-millisecond time for typical content. Under 5ms for 10KB, under 20ms for 100KB. Zero runtime dependencies.

With the ML classifier enabled, expect 50-200ms depending on content length and hardware. Use `scanSync()` for latency-critical paths and `await scan()` when you want ML detection.

### Is my data sent anywhere?

No. Everything runs locally. The regex detectors are pure computation with no network calls. The ML classifier runs an ONNX model on your machine. No content leaves your infrastructure. The only network call is the one-time model download (~165MB) on first use, which can be skipped by bundling the model in your deployment.

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for setup and workflow details.

Areas where contributions are especially valuable:
- New adversarial samples for the evaluation suite (`scripts/eval/samples.ts`)
- New detection patterns for the pattern database (`src/patterns/default-patterns.ts`)
- Custom detectors for novel attack vectors
- Research on the open questions above

## Research Foundation

This project implements defenses based on the systematic framework proposed in:

> Franklin, M., Tomasev, N., Jacobs, J., Leibo, J.Z., & Osindero, S. (2026). *AI Agent Traps*. Google DeepMind. [papers.ssrn.com/sol3/papers.cfm?abstract_id=6372438](https://papers.ssrn.com/sol3/papers.cfm?abstract_id=6372438)

## License

MIT
