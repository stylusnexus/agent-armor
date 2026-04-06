# Agent Armor

Open-source security framework for AI agents. Detects and defends against **AI Agent Traps** — adversarial content designed to manipulate, deceive, or exploit autonomous AI agents.

Built on the taxonomy from [AI Agent Traps](https://arxiv.org/abs/2506.01559) (Franklin et al., Google DeepMind, 2025).

## The Problem

As AI agents browse the web, process documents, and interact with external data, they encounter a new attack surface: **the information environment itself**. Malicious content can be engineered to hijack agent behavior through hidden instructions, poisoned knowledge bases, embedded jailbreaks, and more — all invisible to the human overseer.

Agent Armor provides a defense-in-depth pipeline that scans content at every stage of the agent lifecycle.

## Attack Categories Covered

| Category | Target | Status | What It Detects |
|---|---|---|---|
| **Content Injection** | Perception | MVP | Hidden HTML/CSS instructions, metadata injection, dynamic cloaking artifacts, syntactic masking |
| **Behavioural Control** | Action | MVP | Embedded jailbreak sequences, data exfiltration patterns, sub-agent spawning traps |
| **Cognitive State** | Memory | Planned | RAG knowledge poisoning, latent memory poisoning, contextual learning manipulation |
| **Semantic Manipulation** | Reasoning | Planned | Biased framing/priming, oversight evasion, persona hyperstition |
| **Systemic** | Multi-Agent | Planned | Congestion traps, interdependence cascades, tacit collusion, compositional fragments, sybil attacks |
| **Human-in-the-Loop** | Overseer | Planned | Approval fatigue induction, social engineering via compromised agent |

## Quick Start

```bash
npm install agent-armor
```

```typescript
import { AgentArmor } from 'agent-armor';

const armor = new AgentArmor();

// Scan web content before it enters your agent's context
const result = armor.scanContent(htmlString);

if (result.threats.length > 0) {
  console.warn('Threats detected:', result.threats);
  // Use result.sanitized for cleaned content
}

// Scan retrieved RAG chunks before prompt assembly
const ragResult = armor.scanRAGChunks(retrievedDocuments);

// Scan agent output before it reaches the user
const outputResult = armor.scanOutput(agentResponse);
```

## Architecture

Agent Armor operates as a middleware pipeline with three interception points:

```
External Content → [Pre-Ingestion Scanner] → Agent Context
                                                    ↓
                   [Post-Retrieval Scanner] ← RAG/Memory Store
                                                    ↓
                   [Pre-Execution Scanner]  → Agent Output → User
```

Each scanner runs a configurable set of **detectors** — modular functions that check for specific trap patterns:

```typescript
const armor = new AgentArmor({
  // Enable/disable specific detectors
  contentInjection: {
    hiddenHTML: true,        // CSS display:none, off-screen positioning
    metadataInjection: true, // aria-label, HTML comments with instructions
    syntacticMasking: true,  // Markdown/LaTeX payload hiding
  },
  behaviouralControl: {
    jailbreakPatterns: true, // Known jailbreak sequence detection
    exfiltrationURLs: true,  // Suspicious URL patterns in instructions
    privilegeEscalation: true, // Sub-agent spawning triggers
  },
  // Strictness level affects false positive tolerance
  strictness: 'balanced', // 'permissive' | 'balanced' | 'strict'
});
```

## Detectors

### Content Injection (P0)

- **HiddenHTMLDetector** — Finds instructions hidden via CSS (`display:none`, `visibility:hidden`, off-screen positioning, background-color matching text)
- **MetadataInjectionDetector** — Scans HTML comments, `aria-label`, `alt` attributes, `meta` tags for injected instructions
- **DynamicCloakingDetector** — Detects JavaScript patterns that serve different content to agents vs humans
- **SyntacticMaskingDetector** — Identifies payloads hidden in Markdown link text, LaTeX commands, or formatting syntax

### Behavioural Control (P0)

- **JailbreakPatternDetector** — Pattern-matches against known jailbreak templates (DAN, role-play bypasses, educational framing exploits)
- **ExfiltrationDetector** — Flags instructions that attempt to encode and transmit context data to external URLs
- **SubAgentSpawningDetector** — Detects instructions that try to instantiate new agents or escalate tool permissions

## Framework Agnostic

Agent Armor works with any LLM agent framework:

- **LangChain / LangGraph** — Use as a preprocessing step in your chain
- **Claude Code / Anthropic SDK** — Drop into tool result processing
- **OpenAI Agents SDK** — Wrap tool outputs before context assembly
- **AutoGen / CrewAI** — Add as an inter-agent message filter
- **Custom agents** — Call directly in your pipeline

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and contribution guidelines.

## Research Foundation

This project implements defenses based on the systematic framework proposed in:

> Franklin, M., Tomasev, N., Jacobs, J., Leibo, J.Z., & Osindero, S. (2025). *AI Agent Traps*. Google DeepMind.

## License

MIT
