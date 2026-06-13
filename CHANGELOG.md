# Changelog

All notable changes to this project will be documented in this file.

This project follows [Semantic Versioning](https://semver.org/). Pre-1.0, minor versions may contain breaking changes.

<!-- New entries are generated automatically by release-please from Conventional
Commit messages on merge to main. Do not edit unreleased entries by hand. -->

## [0.2.7](https://github.com/stylusnexus/agent-armor/compare/v0.2.6...v0.2.7) (2026-06-13)


### Added

* **eval:** CI detection-quality gate + stateful multi-turn harness ([#35](https://github.com/stylusnexus/agent-armor/issues/35)) ([#48](https://github.com/stylusnexus/agent-armor/issues/48)) ([40f9d8e](https://github.com/stylusnexus/agent-armor/commit/40f9d8e212f8d1849f5518f02d73925464ab6948))
* **session:** scanSession API + cross-turn split-payload detection ([#35](https://github.com/stylusnexus/agent-armor/issues/35) Phases 0–1) ([#50](https://github.com/stylusnexus/agent-armor/issues/50)) ([ab1821e](https://github.com/stylusnexus/agent-armor/commit/ab1821e325aacc354a28ea323ada165052fc1f79))


### Fixed

* **patterns:** detect credential-harvest-then-send-to-URL exfiltration ([#49](https://github.com/stylusnexus/agent-armor/issues/49)) ([#51](https://github.com/stylusnexus/agent-armor/issues/51)) ([83fd063](https://github.com/stylusnexus/agent-armor/commit/83fd063c3f7830a29da9f293fb7fa3d6b5aa8b2b))


### Documentation

* fix stale eval-sample count in README prose (71 -&gt; 103) ([#46](https://github.com/stylusnexus/agent-armor/issues/46)) ([8fd216d](https://github.com/stylusnexus/agent-armor/commit/8fd216d065dc4fdbeb9cb693f8b7b22dac1896dd))
* **session:** document scanSession split-payload, defer accumulation to ML ([#35](https://github.com/stylusnexus/agent-armor/issues/35)) ([#53](https://github.com/stylusnexus/agent-armor/issues/53)) ([07c50b4](https://github.com/stylusnexus/agent-armor/commit/07c50b42d2a1ebb7111218d07ed8c995fe4113ad))

## [0.2.6](https://github.com/stylusnexus/agent-armor/compare/v0.2.5...v0.2.6) (2026-06-13)


### Added

* add ML data augmentation pipeline scripts ([f1fb88b](https://github.com/stylusnexus/agent-armor/commit/f1fb88bd39d3cc44d5760aa58bf7065733731dcc))
* add transport-integrity taxonomy category ([#26](https://github.com/stylusnexus/agent-armor/issues/26)) ([5c73801](https://github.com/stylusnexus/agent-armor/commit/5c73801c035ff050377cb726cf7b8c9a947ca010))
* detection hardening — unicode normalization + scanner-directed verdict suppression ([#42](https://github.com/stylusnexus/agent-armor/issues/42)) ([67ee749](https://github.com/stylusnexus/agent-armor/commit/67ee749238d7546b73d57efc36c6a8f367c8018c))
* retrain ML classifier on 2,228 samples (7x previous) ([344035e](https://github.com/stylusnexus/agent-armor/commit/344035ebd49302684ed78948ec9110bc79fc21f6))


### Fixed

* address transport-integrity PR review feedback ([159c6d8](https://github.com/stylusnexus/agent-armor/commit/159c6d86eb1791fae75d3e0048fe33fbdf203fe7))


### Documentation

* **examples:** add config-file scanning example (rules-file backdoor) ([#45](https://github.com/stylusnexus/agent-armor/issues/45)) ([58d0a73](https://github.com/stylusnexus/agent-armor/commit/58d0a737e11d898fabdebabd88643819db7fb3af))
* update ML model size to ~165MB (v2 retrain) ([99e2bea](https://github.com/stylusnexus/agent-armor/commit/99e2beac35b01d4be67e94c211a9bf81285e79b0))

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
