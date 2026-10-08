# Changelog

## [0.1.7](https://github.com/stylusnexus/agent-armor/compare/agentarmor-ml-v0.1.6...agentarmor-ml-v0.1.7) (2026-10-08)


### Fixed

* **ml:** follow relative redirects on download ([c4e39a0](https://github.com/stylusnexus/agent-armor/commit/c4e39a05f42a646a02cf81acf01c9300e10a3619)), closes [#288](https://github.com/stylusnexus/agent-armor/issues/288)

## [0.1.6](https://github.com/stylusnexus/agent-armor/compare/agentarmor-ml-v0.1.5...agentarmor-ml-v0.1.6) (2026-10-08)


### Fixed

* **ml:** pin the model revision, fix model card ([aef8fea](https://github.com/stylusnexus/agent-armor/commit/aef8fea479a5b161b4200c5c7cff2b2a25aea11b))
* **ml:** read text with the model's tokenizer ([42a6d74](https://github.com/stylusnexus/agent-armor/commit/42a6d74f371232e44dba8b1235094776e5256e3e)), closes [#271](https://github.com/stylusnexus/agent-armor/issues/271)
* **ml:** report a skipped ML result in the scan ([5afbc4f](https://github.com/stylusnexus/agent-armor/commit/5afbc4f2115ef66f73721191167af0de94ee19e1)), closes [#278](https://github.com/stylusnexus/agent-armor/issues/278) [#279](https://github.com/stylusnexus/agent-armor/issues/279)


### Documentation

* **ml:** state the classifier's limits on its npm page ([2300888](https://github.com/stylusnexus/agent-armor/commit/2300888995113f93bc47960f762c26d8b878bb0b)), closes [#212](https://github.com/stylusnexus/agent-armor/issues/212)

## [0.1.5](https://github.com/stylusnexus/agent-armor/compare/agentarmor-ml-v0.1.4...agentarmor-ml-v0.1.5) (2026-10-02)


### Fixed

* **ml:** patch dev-tool vulnerabilities ([3b75579](https://github.com/stylusnexus/agent-armor/commit/3b75579ffb72b760f299e8cd6838e2a6295c978a))
* **ml:** patch dev-tool vulnerabilities ([97b9448](https://github.com/stylusnexus/agent-armor/commit/97b9448eda5a1214de1c900d9cc5538eff2b95dc))
* **ml:** patch dev-tool vulnerabilities ([#151](https://github.com/stylusnexus/agent-armor/issues/151)) ([3b75579](https://github.com/stylusnexus/agent-armor/commit/3b75579ffb72b760f299e8cd6838e2a6295c978a))

## [0.1.4](https://github.com/stylusnexus/agent-armor/compare/agentarmor-ml-v0.1.3...agentarmor-ml-v0.1.4) (2026-08-07)


### Fixed

* **ml:** raise typed errors from Tokenizer.fromFile on a malformed tokenizer.json ([#104](https://github.com/stylusnexus/agent-armor/issues/104)) ([2ba996b](https://github.com/stylusnexus/agent-armor/commit/2ba996b0b583d65e6016c39b1a8bd2eccdf0733b)), closes [#103](https://github.com/stylusnexus/agent-armor/issues/103)

## [0.1.3](https://github.com/stylusnexus/agent-armor/compare/agentarmor-ml-v0.1.2...agentarmor-ml-v0.1.3) (2026-07-09)


### Added

* @stylusnexus/agentarmor-ml companion package ([#20](https://github.com/stylusnexus/agent-armor/issues/20)) ([104bc7b](https://github.com/stylusnexus/agent-armor/commit/104bc7b58f43a8e36c8bbe77d7b82db8f4b34422))
* audit-evidence records (AuditRecord + evidence-package aggregation) ([#77](https://github.com/stylusnexus/agent-armor/issues/77)) ([cc024b2](https://github.com/stylusnexus/agent-armor/commit/cc024b25e8ccb3ddbb731d1dac73f8b9cca4b849))
* **eval:** CI detection-quality gate + stateful multi-turn harness ([#35](https://github.com/stylusnexus/agent-armor/issues/35)) ([#48](https://github.com/stylusnexus/agent-armor/issues/48)) ([40f9d8e](https://github.com/stylusnexus/agent-armor/commit/40f9d8e212f8d1849f5518f02d73925464ab6948))
* **ml:** retrain model with 14 labels (P0 + P1 categories) ([#23](https://github.com/stylusnexus/agent-armor/issues/23)) ([65caf77](https://github.com/stylusnexus/agent-armor/commit/65caf7745b8c1b75735096dde72fb3950c3aaaf9))
* retrain ML classifier on 2,228 samples (7x previous) ([344035e](https://github.com/stylusnexus/agent-armor/commit/344035ebd49302684ed78948ec9110bc79fc21f6))


### Fixed

* update AI Agent Traps paper link from arxiv to SSRN ([d616b03](https://github.com/stylusnexus/agent-armor/commit/d616b03fd4564e0aaf6398ae686e8feb81ec2cfb))


### Documentation

* add CHANGELOG, SECURITY.md, ML README, fix CONTRIBUTING URL, improve PR template ([f3f2ce0](https://github.com/stylusnexus/agent-armor/commit/f3f2ce01c5a0ef25ad21b2b360853a75d547c503))
* add FAQ, real-world incidents, audience examples, bump to v0.2.3 ([648a5e0](https://github.com/stylusnexus/agent-armor/commit/648a5e0c493c630d03761a60e24b1ed7d4f16be8))
* generated API reference (TypeDoc) published to agentarmor.dev ([#74](https://github.com/stylusnexus/agent-armor/issues/74)) ([39b349c](https://github.com/stylusnexus/agent-armor/commit/39b349c4d7078ec48747e6f5e1c1e0f9b204f580))
* update ML model size to ~165MB (v2 retrain) ([99e2bea](https://github.com/stylusnexus/agent-armor/commit/99e2beac35b01d4be67e94c211a9bf81285e79b0))
