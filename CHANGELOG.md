# Changelog

All notable changes to this project will be documented in this file.

This project follows [Semantic Versioning](https://semver.org/). Pre-1.0, minor versions may contain breaking changes.

<!-- New entries are generated automatically by release-please from Conventional
Commit messages on merge to main. Do not edit unreleased entries by hand. -->

## [0.2.21](https://github.com/stylusnexus/agent-armor/compare/v0.2.20...v0.2.21) (2026-10-05)


### Added

* **detectors:** add first feed-refresh batch of patterns ([#220](https://github.com/stylusnexus/agent-armor/issues/220)) ([4a1f778](https://github.com/stylusnexus/agent-armor/commit/4a1f778d0d17d1710ed08c8daf6b413166f4ad6a)), closes [#215](https://github.com/stylusnexus/agent-armor/issues/215)
* **detectors:** follow CommonMark label rules in reference scan ([#223](https://github.com/stylusnexus/agent-armor/issues/223)) ([6242ad6](https://github.com/stylusnexus/agent-armor/commit/6242ad65b4e69b05eab9661ff5626da1990be9be))
* **detectors:** read blocks and inline text as a renderer does ([#229](https://github.com/stylusnexus/agent-armor/issues/229)) ([2a222c4](https://github.com/stylusnexus/agent-armor/commit/2a222c41b92db6ec8b9be8b618010c470bfad143))
* **detectors:** scan reference-style image exfiltration in code ([#221](https://github.com/stylusnexus/agent-armor/issues/221)) ([6967f58](https://github.com/stylusnexus/agent-armor/commit/6967f5863bc33a3742854b47ceb45ead2d38ec99))


### Fixed

* **detectors:** match labels by quote context ([#231](https://github.com/stylusnexus/agent-armor/issues/231)) ([9097cab](https://github.com/stylusnexus/agent-armor/commit/9097caba94eba18ad9651cd339f0ee252d5a5156)), closes [#227](https://github.com/stylusnexus/agent-armor/issues/227)
* **detectors:** read reference images as a renderer does ([#228](https://github.com/stylusnexus/agent-armor/issues/228)) ([3f166ef](https://github.com/stylusnexus/agent-armor/commit/3f166ef60474b290f433b038988e3d3a53db23d8))
* **detectors:** sanitize definitions with images ([#230](https://github.com/stylusnexus/agent-armor/issues/230)) ([3d5ebac](https://github.com/stylusnexus/agent-armor/commit/3d5ebac39304217ba9aa6f98a4021078285a6953)), closes [#226](https://github.com/stylusnexus/agent-armor/issues/226)
* **detectors:** widen the agent-command addressee ([#214](https://github.com/stylusnexus/agent-armor/issues/214)) ([cdac59c](https://github.com/stylusnexus/agent-armor/commit/cdac59c94deb1bba168c604f8d6f770a8b3d74d5)), closes [#166](https://github.com/stylusnexus/agent-armor/issues/166)
* **detectors:** widen the agent-command addressee again ([#216](https://github.com/stylusnexus/agent-armor/issues/216)) ([45bd0e9](https://github.com/stylusnexus/agent-armor/commit/45bd0e91801fde3b9bfdc3ad5d13086093d48864)), closes [#213](https://github.com/stylusnexus/agent-armor/issues/213)
* **patterns:** scan in linear time ([#209](https://github.com/stylusnexus/agent-armor/issues/209)) ([85d8ca8](https://github.com/stylusnexus/agent-armor/commit/85d8ca84e8a8e2a8938991e0f74cc8134620f4a1))
* **sanitize:** merge edits across detectors ([#211](https://github.com/stylusnexus/agent-armor/issues/211)) ([e86f2c3](https://github.com/stylusnexus/agent-armor/commit/e86f2c3ea140d642e3d3491757d86f274b2d2a21))


### Documentation

* add AGENTS.md and shared agent skills ([#210](https://github.com/stylusnexus/agent-armor/issues/210)) ([e861ae1](https://github.com/stylusnexus/agent-armor/commit/e861ae1d840ec384fb4f9afa3fa49fbc8d56ccf3))
* add the refresh-attack-feeds skill ([#217](https://github.com/stylusnexus/agent-armor/issues/217)) ([84910ea](https://github.com/stylusnexus/agent-armor/commit/84910eaf972141cf45c1b8df630ec5dd0cb9c6ee))

## [0.2.20](https://github.com/stylusnexus/agent-armor/compare/v0.2.19...v0.2.20) (2026-10-04)


### Documentation

* **readme:** add ci and downloads badges ([#196](https://github.com/stylusnexus/agent-armor/issues/196)) ([9c5e7b3](https://github.com/stylusnexus/agent-armor/commit/9c5e7b31cf77e2465d2c6e7272cf4dd514cd8ec8))
* **site:** add icon, favicon and social card ([#198](https://github.com/stylusnexus/agent-armor/issues/198)) ([15f5c88](https://github.com/stylusnexus/agent-armor/commit/15f5c886269cf749f86c27f466454ffddc7b2a08))

## [0.2.19](https://github.com/stylusnexus/agent-armor/compare/v0.2.18...v0.2.19) (2026-10-04)


### Fixed

* **core:** keep credential evidence masked ([#191](https://github.com/stylusnexus/agent-armor/issues/191)) ([5160b26](https://github.com/stylusnexus/agent-armor/commit/5160b26a03cbe222efbe663c93c02b5474f4836b))


### Documentation

* **readme:** add a keeping up to date section ([#190](https://github.com/stylusnexus/agent-armor/issues/190)) ([de7d2de](https://github.com/stylusnexus/agent-armor/commit/de7d2ded12b6517baf9a668ae9dfc96b27fda0ff))
* **readme:** fix npx name and unsafe guidance ([#193](https://github.com/stylusnexus/agent-armor/issues/193)) ([2388fc4](https://github.com/stylusnexus/agent-armor/commit/2388fc43d62b9149ad24e064ab3acbac42c263c8)), closes [#183](https://github.com/stylusnexus/agent-armor/issues/183) [#185](https://github.com/stylusnexus/agent-armor/issues/185)

## [0.2.18](https://github.com/stylusnexus/agent-armor/compare/v0.2.17...v0.2.18) (2026-10-03)


### Fixed

* **core:** keep findings on very large inputs ([6ccc7a0](https://github.com/stylusnexus/agent-armor/commit/6ccc7a05cc1d5a7e79b3374f199322467b5cc31f))
* **detectors:** catch quoted agent-command forms ([#165](https://github.com/stylusnexus/agent-armor/issues/165)) ([c6db2b3](https://github.com/stylusnexus/agent-armor/commit/c6db2b336ebd900038c4c04c376ecd8e8a45bdf2)), closes [#159](https://github.com/stylusnexus/agent-armor/issues/159)


### Performance

* **detectors:** sanitize in one pass ([561de1d](https://github.com/stylusnexus/agent-armor/commit/561de1d100c8cc7046360d29154bf6c7c8e99d31))
* **detectors:** sanitize in one pass ([2a0ee47](https://github.com/stylusnexus/agent-armor/commit/2a0ee479a75fb19c2763da7dc9308947a9483798)), closes [#160](https://github.com/stylusnexus/agent-armor/issues/160)
* **detectors:** sanitize in one pass, keep findings on large inputs ([#168](https://github.com/stylusnexus/agent-armor/issues/168)) ([561de1d](https://github.com/stylusnexus/agent-armor/commit/561de1d100c8cc7046360d29154bf6c7c8e99d31))


### Documentation

* **api:** regenerate AgentArmor source line numbers ([#171](https://github.com/stylusnexus/agent-armor/issues/171)) ([1003de6](https://github.com/stylusnexus/agent-armor/commit/1003de61a4ddde0c8eb7b0cb3d2468970988a0cf))

## [0.2.17](https://github.com/stylusnexus/agent-armor/compare/v0.2.16...v0.2.17) (2026-10-03)


### Added

* **detectors:** flag agent-directed commands ([#157](https://github.com/stylusnexus/agent-armor/issues/157)) ([2c7e3c3](https://github.com/stylusnexus/agent-armor/commit/2c7e3c33dbdbaed605de50683338235b7b3e56fa)), closes [#110](https://github.com/stylusnexus/agent-armor/issues/110)


### Documentation

* **readme:** note quoted attacks can be flagged ([#158](https://github.com/stylusnexus/agent-armor/issues/158)) ([ca2e507](https://github.com/stylusnexus/agent-armor/commit/ca2e5070daa7af862b5cbc43719feaec737db05d))

## [0.2.16](https://github.com/stylusnexus/agent-armor/compare/v0.2.15...v0.2.16) (2026-10-03)


### Fixed

* **ml:** patch dev-tool vulnerabilities ([3b75579](https://github.com/stylusnexus/agent-armor/commit/3b75579ffb72b760f299e8cd6838e2a6295c978a))
* **ml:** patch dev-tool vulnerabilities ([97b9448](https://github.com/stylusnexus/agent-armor/commit/97b9448eda5a1214de1c900d9cc5538eff2b95dc))
* **ml:** patch dev-tool vulnerabilities ([#151](https://github.com/stylusnexus/agent-armor/issues/151)) ([3b75579](https://github.com/stylusnexus/agent-armor/commit/3b75579ffb72b760f299e8cd6838e2a6295c978a))

## [0.2.15](https://github.com/stylusnexus/agent-armor/compare/v0.2.14...v0.2.15) (2026-08-06)


### Added

* **content-injection:** steganographic-payload detector — closes ASCII smuggling bypass ([#69](https://github.com/stylusnexus/agent-armor/issues/69)) ([#102](https://github.com/stylusnexus/agent-armor/issues/102)) ([0aa2ecc](https://github.com/stylusnexus/agent-armor/commit/0aa2ecc075daf1d424a1fe46a9225683835daa75))


### Fixed

* **ml:** raise typed errors from Tokenizer.fromFile on a malformed tokenizer.json ([#104](https://github.com/stylusnexus/agent-armor/issues/104)) ([2ba996b](https://github.com/stylusnexus/agent-armor/commit/2ba996b0b583d65e6016c39b1a8bd2eccdf0733b)), closes [#103](https://github.com/stylusnexus/agent-armor/issues/103)


### Documentation

* **work-plan:** mark launch-infra shipped — publish path proven end-to-end ([#95](https://github.com/stylusnexus/agent-armor/issues/95)) ([ee73267](https://github.com/stylusnexus/agent-armor/commit/ee7326713b223132807c69ed0ffca945cd3313de))

## [0.2.14](https://github.com/stylusnexus/agent-armor/compare/v0.2.13...v0.2.14) (2026-08-06)


### Added

* **transport-integrity:** credential exposure detector ([#28](https://github.com/stylusnexus/agent-armor/issues/28)) ([#94](https://github.com/stylusnexus/agent-armor/issues/94)) ([0505bc7](https://github.com/stylusnexus/agent-armor/commit/0505bc709ff987fdaa1b060d533d65acf4655408))


### Fixed

* update status of [#35](https://github.com/stylusnexus/agent-armor/issues/35) to reflect completion ([442409d](https://github.com/stylusnexus/agent-armor/commit/442409de6d56989f7b53850f38db4d18410f4273))

## [0.2.13](https://github.com/stylusnexus/agent-armor/compare/v0.2.12...v0.2.13) (2026-07-09)


### Documentation

* mark [#70](https://github.com/stylusnexus/agent-armor/issues/70)'s manual npm-publish blockers cleared in launch-infra track ([#91](https://github.com/stylusnexus/agent-armor/issues/91)) ([8bd169d](https://github.com/stylusnexus/agent-armor/commit/8bd169dcb771a879d1237c6906cf596e4e91647b))

## [0.2.12](https://github.com/stylusnexus/agent-armor/compare/v0.2.11...v0.2.12) (2026-07-09)


### Fixed

* **ci:** upgrade npm before publish so OIDC Trusted Publishing works ([#88](https://github.com/stylusnexus/agent-armor/issues/88)) ([#89](https://github.com/stylusnexus/agent-armor/issues/89)) ([e164658](https://github.com/stylusnexus/agent-armor/commit/e16465872bbc5731860b1ec94a57b5dd7bd674d8))

## [0.2.11](https://github.com/stylusnexus/agent-armor/compare/v0.2.10...v0.2.11) (2026-07-09)


### Fixed

* **ci:** set separate-pull-requests to fix stuck root-only releases ([#85](https://github.com/stylusnexus/agent-armor/issues/85)) ([#86](https://github.com/stylusnexus/agent-armor/issues/86)) ([218310c](https://github.com/stylusnexus/agent-armor/commit/218310c17d60e145f0be8b12091d430088bc247f))

## [0.2.10](https://github.com/stylusnexus/agent-armor/compare/v0.2.9...v0.2.10) (2026-07-09)


### Documentation

* fix stale eval numbers in README prose (103-&gt;105, 81.8/90.9-&gt;82.1/91.0) ([#83](https://github.com/stylusnexus/agent-armor/issues/83)) ([96fd9fa](https://github.com/stylusnexus/agent-armor/commit/96fd9fa8991f4bb37c2f994e1fc11c6ea63cf53f))

## [0.2.9](https://github.com/stylusnexus/agent-armor/compare/v0.2.8...v0.2.9) (2026-07-09)


### Added

* cross-turn ML accumulation windowing in session scan ([#35](https://github.com/stylusnexus/agent-armor/issues/35) step 1) ([#62](https://github.com/stylusnexus/agent-armor/issues/62)) ([b83ed1b](https://github.com/stylusnexus/agent-armor/commit/b83ed1bdd77d122c1e3ad2937f84f4166e0a35fb))


### Fixed

* **ci:** correct release-please output key for publish-core ([#81](https://github.com/stylusnexus/agent-armor/issues/81)) ([#82](https://github.com/stylusnexus/agent-armor/issues/82)) ([d881d30](https://github.com/stylusnexus/agent-armor/commit/d881d30f5632a0592a2b77aead9eb44b23bf4ee4))

## [0.2.8](https://github.com/stylusnexus/agent-armor/compare/v0.2.7...v0.2.8) (2026-07-09)


### Added

* add computed riskLevel roll-up to ScanResult ([#34](https://github.com/stylusnexus/agent-armor/issues/34)) ([#60](https://github.com/stylusnexus/agent-armor/issues/60)) ([1a63340](https://github.com/stylusnexus/agent-armor/commit/1a63340856232e58145899bbc14690ab8d1063a5))
* agentarmor CLI with JSON/SARIF output for CI scanning ([#73](https://github.com/stylusnexus/agent-armor/issues/73)) ([5331e14](https://github.com/stylusnexus/agent-armor/commit/5331e14d0f57420a6dcd4a8bdca0e21af4572121))
* allowlist-based pre-execution action gate ([#57](https://github.com/stylusnexus/agent-armor/issues/57)) ([#61](https://github.com/stylusnexus/agent-armor/issues/61)) ([766af56](https://github.com/stylusnexus/agent-armor/commit/766af562d9edbb516394cdc4b199836729789b11))
* audit-evidence records (AuditRecord + evidence-package aggregation) ([#77](https://github.com/stylusnexus/agent-armor/issues/77)) ([cc024b2](https://github.com/stylusnexus/agent-armor/commit/cc024b25e8ccb3ddbb731d1dac73f8b9cca4b849))
* extensible diagnostics/event system (warn, error, detectorSkipped) ([#76](https://github.com/stylusnexus/agent-armor/issues/76)) ([d65871c](https://github.com/stylusnexus/agent-armor/commit/d65871c148f03100e3973850359453cfb21088dd))


### Fixed

* **action-gate:** deny home-directory (~) and URL/stream-wrapper paths; pin SecLists LFI fuzz eval ([#63](https://github.com/stylusnexus/agent-armor/issues/63)) ([0611b24](https://github.com/stylusnexus/agent-armor/commit/0611b24b0fe96b8c861c4dadc26c541139e5e61c))


### Documentation

* add deterministic-vs-probabilistic positioning to README and llms.txt ([#58](https://github.com/stylusnexus/agent-armor/issues/58)) ([637a4d4](https://github.com/stylusnexus/agent-armor/commit/637a4d4d2ddb6c059fcea0b0521a2222b793813c))
* generated API reference (TypeDoc) published to agentarmor.dev ([#74](https://github.com/stylusnexus/agent-armor/issues/74)) ([39b349c](https://github.com/stylusnexus/agent-armor/commit/39b349c4d7078ec48747e6f5e1c1e0f9b204f580))
* **site:** refresh llms.txt + landing for 0.2.7 (eval numbers, multi-turn) ([#55](https://github.com/stylusnexus/agent-armor/issues/55)) ([cd6fb9d](https://github.com/stylusnexus/agent-armor/commit/cd6fb9d622979d3482e23a04b386f09a13da66b7))

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
