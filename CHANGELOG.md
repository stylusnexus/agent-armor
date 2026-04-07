# Changelog

All notable changes to this project will be documented in this file.

This project follows [Semantic Versioning](https://semver.org/). Pre-1.0, minor versions may contain breaking changes.

## [0.2.5] - 2026-04-07

### Added
- 6 new detection patterns: system override declarations, precedence claims, markdown comment injection, bracket-delimited fake system commands, concealment instructions, deceptive display forgery
- 15 new eval samples from 2025-2026 real-world incidents (MCP tool poisoning, RAG vector DB saturation, CamoLeak covert exfiltration, Clinejection supply chain, memory poisoning, HITL dialog forgery) with 5 benign counterparts
- Changelog link in site header nav
- CamoLeak, Clinejection, and MCP tool poisoning added to README "Why This Matters" section

### Changed
- Eval suite expanded to 86 samples (59 adversarial, 27 benign)
- Detection rate at balanced: 89.8% overall (100% on established patterns, 5 of 10 new real-world samples caught by regex)
- Strictness Levels section in README now explains confidence thresholds

## [0.2.4] - 2026-04-07

### Fixed
- `AgentArmor.create()` now correctly defaults `onUnavailable` to `'warn-and-skip'` instead of throwing when ML model is unavailable
- `loadPatterns()` no longer silently drops the ML detector when rebuilding pattern detectors
- Removed `requireInstructions` gate from `cl-learn-from` and `cl-follow-pattern` patterns — these are inherently instructional and don't need a second signal check
- Corrected eval sample count across all docs (71 samples: 49 adversarial, 22 benign)
- Corrected Franklin et al. paper date from 2025 to 2026 across all references
- Removed stale "NOT tested" note for cognitive-state and semantic-manipulation in real-world validation example

### Changed
- Eval detection rate at balanced/strict now 100% (up from 98%) after pattern fix
- Permissive detection rate updated to 87.8% (reflects current sample set)

### Added
- Strictness Levels section in README explaining confidence thresholds and tradeoffs
- Strictness explanations in landing page and llms.txt

## [0.2.3] - 2026-04-06

### Fixed
- Updated AI Agent Traps paper link from arXiv to SSRN

## [0.2.2] - 2026-04-06

### Added
- Static landing page for agentarmor.dev
- SEO, structured data, llms.txt, and alpha badge
- Footer updated to Stylus Nexus Holdings, LLC

## [0.2.1] - 2026-04-06

### Fixed
- Corrected repository URL in CONTRIBUTING.md
- Updated eval result description in README

### Added
- `SECURITY.md` with responsible disclosure policy
- `CHANGELOG.md`
- Examples section in README
- `packages/ml/README.md` for the ML companion package

## [0.2.0] - 2026-04-05

### Added
- **P1 detectors** — Cognitive State (RAG poisoning, memory poisoning, contextual learning) and Semantic Manipulation (biased framing, oversight evasion, persona hyperstition)
- `AgentArmor.create(config)` async factory with ML classifier support
- `AgentArmor.regexOnly(config)` sync-only factory
- `scanSync()`, `scanRAGChunksSync()`, `scanOutputSync()` sync scan methods
- `scan()`, `scanRAGChunks()`, `scanOutput()` async scan methods
- `source` field on `Threat` interface (`'pattern' | 'ml' | 'custom'`)
- `@stylusnexus/agentarmor-ml` companion package — ONNX-based DeBERTa-v3-small classifier
- ML data pipeline (`ml/data/`) and training pipeline (`ml/train/`)
- Integration examples: RAG pipeline, Express middleware, web content scanner, ML classifier, custom detector, real-world validation
- `CONTRIBUTING.md`, issue templates, PR template

### Changed
- Pattern database updated to v0.4.0 with P1 category patterns
- `fetchLatestPatterns(url)` now requires a URL parameter

### Breaking
- `Threat` interface requires `source` field
- Sync scan methods renamed (e.g. `scanContent()` -> `scanSync()`)
- `fetchLatestPatterns()` requires URL argument

## [0.1.0] - 2026-03-28

### Added
- Initial release
- **P0 detectors** — Content Injection (hidden HTML, metadata injection, dynamic cloaking, syntactic masking) and Behavioural Control (jailbreak patterns, data exfiltration, sub-agent spawning)
- Pattern-based detection with configurable strictness levels
- Sanitization pipeline
- Updatable pattern database with `fetchLatestPatterns()` and `loadPatterns()`
- Evaluation suite with curated adversarial and benign samples
