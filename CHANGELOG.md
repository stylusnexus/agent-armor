# Changelog

All notable changes to this project will be documented in this file.

This project follows [Semantic Versioning](https://semver.org/). Pre-1.0, minor versions may contain breaking changes.

<!-- New entries are generated automatically by release-please from Conventional
Commit messages on merge to main. Do not edit unreleased entries by hand. -->

## [0.2.27](https://github.com/stylusnexus/agent-armor/compare/v0.2.26...v0.2.27) (2026-10-23)


### Fixed

* **ml:** check checksum shape before download ([09d5319](https://github.com/stylusnexus/agent-armor/commit/09d5319c1de196a5bb120db4120c3cbf5c889169))
* **ml:** check checksum shape before download ([ac0848a](https://github.com/stylusnexus/agent-armor/commit/ac0848a046e7492187144655ab9d8a26b1c4b9dc)), closes [#359](https://github.com/stylusnexus/agent-armor/issues/359)
* **patterns:** bump db to 0.9.22 for [#356](https://github.com/stylusnexus/agent-armor/issues/356) ([4b85ccc](https://github.com/stylusnexus/agent-armor/commit/4b85ccca46ada6f26d2efaff23887bcaad78113f))
* **patterns:** bump db to 0.9.22 for [#356](https://github.com/stylusnexus/agent-armor/issues/356) ([546e9ea](https://github.com/stylusnexus/agent-armor/commit/546e9ea7ca5d4f76140176816302f8130e793569))
* **security:** handle comment end bang ([#356](https://github.com/stylusnexus/agent-armor/issues/356)) ([2ae62ea](https://github.com/stylusnexus/agent-armor/commit/2ae62eaf9c2f56ba417b1033e3e1afe1956afcda))


### Documentation

* **api:** sync DEFAULT_PATTERNS source line ([411e285](https://github.com/stylusnexus/agent-armor/commit/411e2857c030c335c8be3ed01c193fa5087be3bf))
* clarify performance and release guidance ([#372](https://github.com/stylusnexus/agent-armor/issues/372)) ([d4656fc](https://github.com/stylusnexus/agent-armor/commit/d4656fc46ed2ffc40cf00fbcc47ae739429618a5))
* clarify performance and release guidance ([#373](https://github.com/stylusnexus/agent-armor/issues/373)) ([e68a56d](https://github.com/stylusnexus/agent-armor/commit/e68a56d6ff932bf63bcf7371a80a373a55e96c7f))
* **ml:** document AGENTARMOR_MODEL_DIR ([c93770f](https://github.com/stylusnexus/agent-armor/commit/c93770f46f58d4127abf29f32089571e2c5ed584))
* **ml:** document AGENTARMOR_MODEL_DIR ([c243f04](https://github.com/stylusnexus/agent-armor/commit/c243f04f3a6311412dc3a1b44d45380a335f78ee)), closes [#360](https://github.com/stylusnexus/agent-armor/issues/360)
* **work-plan:** apply issue housekeeping ([75827cc](https://github.com/stylusnexus/agent-armor/commit/75827ccb5bee00e372fc067841115702ea578876))
* **work-plan:** apply issue housekeeping ([a3b7ad1](https://github.com/stylusnexus/agent-armor/commit/a3b7ad1c05fb5046df0f5a5639a0788f29929c68))
* **work-plan:** close [#178](https://github.com/stylusnexus/agent-armor/issues/178), add [#368](https://github.com/stylusnexus/agent-armor/issues/368), re-rank ([36b46e4](https://github.com/stylusnexus/agent-armor/commit/36b46e44d62930f9edfcc1d58a0afd8f478ef69d))
* **work-plan:** close [#178](https://github.com/stylusnexus/agent-armor/issues/178), add [#368](https://github.com/stylusnexus/agent-armor/issues/368), re-rank ([3ace5ac](https://github.com/stylusnexus/agent-armor/commit/3ace5ac9624d72e3ec7bf4f7b306fe1d88913038))
* **work-plan:** re-rank backlog, add three tracks ([#361](https://github.com/stylusnexus/agent-armor/issues/361)) ([2e59428](https://github.com/stylusnexus/agent-armor/commit/2e594285dfba3c652b8d0afacd7e792a57c52099))
* **work-plan:** sync track corrections ([c361931](https://github.com/stylusnexus/agent-armor/commit/c36193170fb60bfc52c166a4cd1908e65085ec0d))
* **work-plan:** sync track corrections ([03dd688](https://github.com/stylusnexus/agent-armor/commit/03dd68811ce1231929009f41ba74a57904cfa20d))

## [0.2.26](https://github.com/stylusnexus/agent-armor/compare/v0.2.25...v0.2.26) (2026-10-19)


### Fixed

* **cli:** close scan and action gaps ([#343](https://github.com/stylusnexus/agent-armor/issues/343)) ([bf890cf](https://github.com/stylusnexus/agent-armor/commit/bf890cf4222ca66c5091706c930ab50505b16d40)), closes [#184](https://github.com/stylusnexus/agent-armor/issues/184)
* **example:** scan Express arrays safely ([#341](https://github.com/stylusnexus/agent-armor/issues/341)) ([7428a53](https://github.com/stylusnexus/agent-armor/commit/7428a534750d28edaa99e2962432b50e66ab8165)), closes [#185](https://github.com/stylusnexus/agent-armor/issues/185)
* **ml:** verify and bound model artifacts ([#344](https://github.com/stylusnexus/agent-armor/issues/344)) ([4fd60f0](https://github.com/stylusnexus/agent-armor/commit/4fd60f0020eab262345c2ec11ff8b61bc38b1c03)), closes [#186](https://github.com/stylusnexus/agent-armor/issues/186)

## [0.2.25](https://github.com/stylusnexus/agent-armor/compare/v0.2.24...v0.2.25) (2026-10-18)


### Added

* **detectors:** decode and rescan encoded text ([#336](https://github.com/stylusnexus/agent-armor/issues/336)) ([28252db](https://github.com/stylusnexus/agent-armor/commit/28252db42e99600f49639c481500e0bc9cf03897))
* **detectors:** read rot13 without a cue word ([#338](https://github.com/stylusnexus/agent-armor/issues/338)) ([e79cf04](https://github.com/stylusnexus/agent-armor/commit/e79cf0480aab5dede923cca0c7ac374db357b259))
* **detectors:** screen tool calls ([#27](https://github.com/stylusnexus/agent-armor/issues/27), [#30](https://github.com/stylusnexus/agent-armor/issues/30)) ([#330](https://github.com/stylusnexus/agent-armor/issues/330)) ([6b8ccde](https://github.com/stylusnexus/agent-armor/commit/6b8ccde2e430ddd4960f11a4058ab758889d4130))
* **patterns:** add c2 and persistence patterns ([#329](https://github.com/stylusnexus/agent-armor/issues/329)) ([0cae810](https://github.com/stylusnexus/agent-armor/commit/0cae8102d5c71551ac3b641d843b3738cac81ec7))


### Fixed

* **core:** flag degraded scans, check strictness ([#333](https://github.com/stylusnexus/agent-armor/issues/333)) ([7d2b8a4](https://github.com/stylusnexus/agent-armor/commit/7d2b8a425ffeb5f03013130178cc4735fc096db4))
* **core:** validate remote pattern databases ([#335](https://github.com/stylusnexus/agent-armor/issues/335)) ([60ca2ff](https://github.com/stylusnexus/agent-armor/commit/60ca2ff51f674c687f99c2c6ac8cbfd832500120))
* **deps:** bump source-map-js to 1.2.2 ([#314](https://github.com/stylusnexus/agent-armor/issues/314)) ([4c0bdb0](https://github.com/stylusnexus/agent-armor/commit/4c0bdb01c5c4d4943e3cb8ee44efc2b8b5f5976a)), closes [#313](https://github.com/stylusnexus/agent-armor/issues/313)
* **ml:** accept an absolute --dir in download ([#316](https://github.com/stylusnexus/agent-armor/issues/316)) ([ab4c010](https://github.com/stylusnexus/agent-armor/commit/ab4c010678715d630a8be027799c9fcc108b8f38)), closes [#315](https://github.com/stylusnexus/agent-armor/issues/315)
* **patterns:** flag chat sent to outside address ([#334](https://github.com/stylusnexus/agent-armor/issues/334)) ([94331b7](https://github.com/stylusnexus/agent-armor/commit/94331b7732af0d998dba49d5d8334c6292d0ff6b))
* **patterns:** widen conversation exfil forms ([#339](https://github.com/stylusnexus/agent-armor/issues/339)) ([2af1751](https://github.com/stylusnexus/agent-armor/commit/2af17513b42cb8379b8e7859dff0ed637a6f97db))


### Documentation

* **eval:** explain the 11 known false positives ([#331](https://github.com/stylusnexus/agent-armor/issues/331)) ([72305d4](https://github.com/stylusnexus/agent-armor/commit/72305d4984d7417ef361a8764425d18472b1a396))
* **ml:** say the real-document result is tuned ([#323](https://github.com/stylusnexus/agent-armor/issues/323)) ([44561cd](https://github.com/stylusnexus/agent-armor/commit/44561cd0bfab795fed50bf8ea6a03c6bd2df0654)), closes [#298](https://github.com/stylusnexus/agent-armor/issues/298)
* **readme:** name run 7 as the model in 0.1.8 ([#326](https://github.com/stylusnexus/agent-armor/issues/326)) ([cd577ac](https://github.com/stylusnexus/agent-armor/commit/cd577ac4f3f1b58780e3d90abf8717ceed188990)), closes [#325](https://github.com/stylusnexus/agent-armor/issues/325)
* **readme:** state prompt-injection coverage ([#321](https://github.com/stylusnexus/agent-armor/issues/321)) ([d0e1031](https://github.com/stylusnexus/agent-armor/commit/d0e1031ecab373540cd6c94399811f08847c4c0c)), closes [#320](https://github.com/stylusnexus/agent-armor/issues/320)
* **skill:** add advisory feeds to the attack-feed refresh ([#267](https://github.com/stylusnexus/agent-armor/issues/267)) ([45cf00c](https://github.com/stylusnexus/agent-armor/commit/45cf00c602917fbd35fde556faa9123c3d14efc5)), closes [#266](https://github.com/stylusnexus/agent-armor/issues/266)

## [0.2.24](https://github.com/stylusnexus/agent-armor/compare/v0.2.23...v0.2.24) (2026-10-16)


### Added

* **ml:** measure false flags on real documents ([8c4629a](https://github.com/stylusnexus/agent-armor/commit/8c4629a1f9e88851520e667f4ba411737ad2bfea)), closes [#276](https://github.com/stylusnexus/agent-armor/issues/276) [#294](https://github.com/stylusnexus/agent-armor/issues/294)


### Fixed

* **ml:** follow relative redirects on download ([c4e39a0](https://github.com/stylusnexus/agent-armor/commit/c4e39a05f42a646a02cf81acf01c9300e10a3619)), closes [#288](https://github.com/stylusnexus/agent-armor/issues/288)
* **ml:** ship the real-document retrained model ([d7430b2](https://github.com/stylusnexus/agent-armor/commit/d7430b2fe2b12f448e62ac77104ea88b3e79b02a)), closes [#294](https://github.com/stylusnexus/agent-armor/issues/294)
* **patterns:** catch two semantic gaps at strict ([#301](https://github.com/stylusnexus/agent-armor/issues/301)) ([5c6f2eb](https://github.com/stylusnexus/agent-armor/commit/5c6f2ebbdabd4e64c2069a687f9360a978f11901))


### Documentation

* **readme:** state the versioning policy ([#310](https://github.com/stylusnexus/agent-armor/issues/310)) ([0cf435c](https://github.com/stylusnexus/agent-armor/commit/0cf435cb62508f57cbcaa2c726782cf4f138a98e)), closes [#302](https://github.com/stylusnexus/agent-armor/issues/302)

## [0.2.23](https://github.com/stylusnexus/agent-armor/compare/v0.2.22...v0.2.23) (2026-10-08)


### Added

* **detectors:** add dependency substitution ([#256](https://github.com/stylusnexus/agent-armor/issues/256)) ([ff28258](https://github.com/stylusnexus/agent-armor/commit/ff282587fc8464e8fd31b6b90cac881d8817c02e))
* **detectors:** flag poisoned MCP tool descriptions ([#265](https://github.com/stylusnexus/agent-armor/issues/265)) ([c6858a3](https://github.com/stylusnexus/agent-armor/commit/c6858a3a90dc95f2e763fb227020ddd88adae298))


### Fixed

* **ml:** pin the model revision, fix model card ([aef8fea](https://github.com/stylusnexus/agent-armor/commit/aef8fea479a5b161b4200c5c7cff2b2a25aea11b))
* **ml:** read text with the model's tokenizer ([42a6d74](https://github.com/stylusnexus/agent-armor/commit/42a6d74f371232e44dba8b1235094776e5256e3e)), closes [#271](https://github.com/stylusnexus/agent-armor/issues/271)
* **ml:** report a skipped ML result in the scan ([5afbc4f](https://github.com/stylusnexus/agent-armor/commit/5afbc4f2115ef66f73721191167af0de94ee19e1)), closes [#278](https://github.com/stylusnexus/agent-armor/issues/278) [#279](https://github.com/stylusnexus/agent-armor/issues/279)
* **patterns:** catch install-from-URL then commit ([#259](https://github.com/stylusnexus/agent-armor/issues/259)) ([bf952d4](https://github.com/stylusnexus/agent-armor/commit/bf952d49b9d48a05a3f89d6b0452a521d723fbb1))
* **patterns:** catch private repo to public gist ([#261](https://github.com/stylusnexus/agent-armor/issues/261)) ([6f3baab](https://github.com/stylusnexus/agent-armor/commit/6f3baabfc558798bd84a64da2c1bc74b002bfe9b)), closes [#250](https://github.com/stylusnexus/agent-armor/issues/250)
* **patterns:** flag bare sensitive file names again ([#264](https://github.com/stylusnexus/agent-armor/issues/264)) ([639d510](https://github.com/stylusnexus/agent-armor/commit/639d5101c818eaa8b11de958bb39a0699579ab5f))
* **patterns:** stop flagging token docs as file reads ([#263](https://github.com/stylusnexus/agent-armor/issues/263)) ([7d79b9f](https://github.com/stylusnexus/agent-armor/commit/7d79b9f718120fdc683fd35f7cb70d3fa1379c79)), closes [#262](https://github.com/stylusnexus/agent-armor/issues/262)


### Documentation

* **ml:** state the classifier's limits on its npm page ([2300888](https://github.com/stylusnexus/agent-armor/commit/2300888995113f93bc47960f762c26d8b878bb0b)), closes [#212](https://github.com/stylusnexus/agent-armor/issues/212)
* **readme:** drop the unverified count in the FAQ ([#258](https://github.com/stylusnexus/agent-armor/issues/258)) ([7bf8656](https://github.com/stylusnexus/agent-armor/commit/7bf8656e044abd368fd88453cb81d43abfd07f00))
* **readme:** fix the detector count in the FAQ ([#257](https://github.com/stylusnexus/agent-armor/issues/257)) ([99fb488](https://github.com/stylusnexus/agent-armor/commit/99fb48869b8c4c495e529cb41af854e6e176410c))
* **readme:** scan untrusted issue text at strict ([#260](https://github.com/stylusnexus/agent-armor/issues/260)) ([ff6d5bd](https://github.com/stylusnexus/agent-armor/commit/ff6d5bd634add307bdb331f0a85d4b812439ae6c))
* **skill:** add clarification on input failure claims and verification process ([4c4f5a2](https://github.com/stylusnexus/agent-armor/commit/4c4f5a26ce52b650224bf829e9583919798551ff))

## [0.2.22](https://github.com/stylusnexus/agent-armor/compare/v0.2.21...v0.2.22) (2026-10-06)


### Fixed

* **normalize:** strip accents and compose marks ([2b572ff](https://github.com/stylusnexus/agent-armor/commit/2b572ff5c0b5836973917422a2db33b1e9166233)), closes [#243](https://github.com/stylusnexus/agent-armor/issues/243)


### Performance

* **detectors:** sanitize legacy classes in one pass ([#239](https://github.com/stylusnexus/agent-armor/issues/239)) ([51d9b99](https://github.com/stylusnexus/agent-armor/commit/51d9b99ef197b36dafa8a3d80418801ac297e992))


### Documentation

* **readme:** state patterns are English-only ([#240](https://github.com/stylusnexus/agent-armor/issues/240)) ([e462dc5](https://github.com/stylusnexus/agent-armor/commit/e462dc5ae8a24c96d7f9b88d3a0bc97888a1f0d2)), closes [#180](https://github.com/stylusnexus/agent-armor/issues/180)

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
