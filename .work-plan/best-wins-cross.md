---
track: best-wins-cross
status: active
launch_priority: P0
milestone_alignment: v1.0.0
github:
  repo: stylusnexus/agent-armor
  issues: []
  references:
    - 71
    - 69
    - 68
    - 27
    - 37
    - 29
    - 38
    - 40
    - 30
    - 25
    - 32
    - 31
  branches: []
depends_on:
  - detection-hardening
  - transport-integrity
  - ml-v2-retrain
  - enterprise-readiness
  - systemic-traps
  - human-in-the-loop
last_touched: 2026-08-05T22:55
last_handoff: 2026-08-05T22:55
next_up:
  - 71
  - 69
  - 68
blockers: []
---
# Best Wins (convergence track)

**This track owns nothing.** `github.issues` is deliberately empty and every issue below sits in
`github.references` — the toolkit's cross-track construct for surfacing scope without claiming
ownership. Status, session logs, and issue-table upkeep stay in each issue's home track; this
file answers one question the seven topic tracks can't answer individually: *what should we pick
up next?*

Rules of the road:

- **Never `slot` an issue here.** Use `batch-slot <issues> best-wins-cross --reference` so the
  home track keeps ownership. `demote-to-reference` is the repair if one lands here by mistake.
- **Re-rank, don't append.** When something ships or a new issue is filed, redo the ordering
  rather than tacking the new item onto the end.
- **Don't run `canonicalize` on this file** — it would prepend an auto-managed issue table and
  overwrite the hand-written ranking below.
- Ranked 2026-08-05 against the live repo (22 open issues) and the live source, not against the
  issue text alone. Several issue bodies are stale — see "Corrections to the backlog".

## The thing that isn't in any track

Worth stating before the ranking, because it changes how to read it. As of 2026-08-05 the repo
is public with **4 stars, 0 forks** and **614 npm downloads/month** on the core package (73 on
the ML package). The launch is parked pending a date. Detection features don't compound until
there are users to report against them, and the project's own stated near-term goal is
credibility rather than revenue.

So this ranking optimises for **demoable, legible credibility** over raw detector count. That's
why a secret scanner and a supply-chain self-check outrank a paper-faithful anomaly model. None
of it substitutes for picking a launch date.

## Ranking

| Rank | Issue | Home track | Why it wins | Effort | Risk |
|---|---|---|---|---|---|
| ~~1~~ | ~~#28 credential-exposure detector~~ | transport-integrity | **✅ Shipped 2026-08-05** (PR #94, `0505bc7`) — closed #26 with it. 6/6 detection, FP held at 0.0%. | — | — |
| 1 | #71 ML checksum integrity CI | ml-v2-retrain | A security tool that verifies its own supply chain. One scheduled workflow, no secrets, public HF repo. Also blocks publishing an ML version whose checksum disagrees with HuggingFace. | **Low** | Low |
| 2 | #69 item 1 — kill or implement `steganographic-payload` | detection-hardening | A declared-but-dead enum in a public type system reads as a capability claim that isn't real. On a security product that's a trust wart. **Split this item out and ship it alone.** | **Low** | Low (breaking type change if removed) |
| 3 | #68 items 1+3 — bare-rule footgun + aggregate reasons | detection-hardening | The bare-rule footgun is a dangerous default in the *pre-execution gate* — the README warns about it but nothing prevents it. Aggregate reasons make a denial debuggable without bisecting the policy. | Low–Med | Low (fuzz baseline protects it) |
| 4 | #27 tool-call-tampering detector | transport-integrity | The strongest launch narrative available: 0 of 4 major agent frameworks verify response integrity (Liu et al. 2026), citing real router compromises. | Med | **Med–High** — install docs legitimately contain `curl \| sh`; needs hard negatives and careful confidence tuning |
| 5 | #68 items 2+4 — tool globs + `baseDir` | detection-hardening | Both need the SecLists fuzz corpus extended alongside them, so they cost more than 1+3. Real value: `baseDir` gives callers who can't pre-normalise a safe option. | Med | Med |
| 6 | #69 items 2+3 — thin coverage + threshold extraction | detection-hardening | Protects the regression gate that protects every future change. Verified thin: 3 samples each for `dynamic-cloaking`, `syntactic-masking`, `persona-hyperstition`; 4 each for `contextual-learning-trap`, `biased-framing` — against 11 for the best-covered types. | Med (curation grind) | Low |
| 7 | #37 long-context attention-dilution | detection-hardening | Real open detection gap against a documented bypass technique. Cheap heuristic over already-computed match positions and content length. | Med | Med — one open design call (detector vs. pipeline scoring; the issue leans pipeline) |
| 8 | #29 dependency-substitution | transport-integrity | Typosquat/supply-chain angle lands with the same audience as #27 and shares its machinery once #27's patterns exist. Structural approach, no dictionary to maintain. | Med | Med |
| 9 | #38 SOC 2 / ISO 27001 crosswalk | enterprise-readiness | **Newly unblocked** — all three stated dependencies shipped. Docs, not code, written against a real shipped schema (`AuditRecord`, `buildEvidencePackage`). Enterprise credibility asset. | Med (writing) | Low, provided it doesn't over-claim |
| 10 | #40 eval-gated external-feed ingestion | ml-v2-retrain | Highest *strategic* value here — it's the mechanism behind the Pro-tier pattern feed. But design-heavy, and worth more once there's adoption to serve. | **High** | Med |
| 11 | #30 response-anomaly screening | transport-integrity | Marginal value drops sharply once #27 and #28 ship — its highest-weighted feature (shell risk) is #27's, and its secret-pattern feature is #28's. | Med | Med |
| 12 | #25 ML v2 retrain data | ml-v2-retrain | The big lift: ~5,400 labelled samples. High long-term value ("ML demonstrably better than regex" is a monetisation trigger), but weeks, not days. | **High** | Med |
| 13 | #32 transport-integrity ML samples | ml-v2-retrain | Rides #25 plus the #27–#30 detectors. Nothing to do before both. | Med | Low |
| 14 | #31 provider response-envelope signing | transport-integrity | Genuinely future — needs provider cooperation that doesn't exist yet. | High | High |
| 15–21 | #7–#13 systemic + human-in-the-loop | systemic-traps, human-in-the-loop | Correctly deferred, and not referenced by this track. These need real incident signal from real users; building them now means guessing. | High | High |

## Suggested sequencing

Three batches, each independently mergeable:

1. **Credibility batch (days):** ~~#28~~ ✅ → **#71 → #69 item 1**. Two small PRs left. Ends with a
   self-verifying model supply chain and no dead types in the public taxonomy. This is the batch
   to have finished *before* a launch post, not after.
2. **Hardening batch:** #68 items 1+3, then #69 items 2+3. Tightens the pre-execution gate's
   dangerous defaults, then shores up the regression floor everything else stands on.
3. **Transport-integrity batch:** #27 → #29 → #68 items 2+4 → #37. No taxonomy prerequisite
   remains — #26 closed with #28. The paper-backed detector
   story, plus the remaining gate work and the dilution gap.

#38 can run in parallel with any of these — it's writing, not code, and touches nothing the
other batches touch.

## Corrections to the backlog

Found by checking live source rather than trusting issue text. These change the effort estimates
above and should be reflected in the home tracks.

1. **#26 (transport-integrity taxonomy) is substantially already implemented** and is *not* the
   blocker the transport-integrity track's `next_up` implies. Verified live:
   - `TrapCategory` already includes `'transport-integrity'` (`src/types/index.ts:18`)
   - `TransportIntegrityType` is fully defined with all four subtypes (`src/types/index.ts:58`)
     and unioned into `TrapType` (`src/types/index.ts:72`)
   - The `transportIntegrity` config block exists (`src/types/index.ts:534-537`) with all four
     toggles defaulting to `true` (`src/agent-armor.ts:56-60`), merged in the constructor
     (`src/agent-armor.ts:312-314`)
   - `DetectorRegistration.configGroup` already accepts `'transportIntegrity'`
     (`src/agent-armor.ts:118`)

   What's genuinely missing is a `DETECTOR_REGISTRY` entry and a pattern-DB key — and those land
   *with the first detector*, not before it. **Confirmed by shipping it:** #28 supplied both and
   closed #26 in the same PR. The config defaults were indeed already `true`, so the detector went
   out on-by-default for existing users — called out in the PR and the merge commit.

2. **#38's "do not start" deferral is stale.** Its three stated blockers have all shipped: #24
   (diagnostics), #75 (audit-evidence records), and #35 (multi-turn, per detection-hardening's
   2026-07-09 log). The issue body still opens with "Do not start until #24 and #35 have landed."
   Re-triage it.

3. **#35 is marked shipped in the track but is still OPEN on GitHub** (`state=OPEN`,
   `closedAt=null`). detection-hardening marks it ✅ Shipped as of 2026-07-09 and commit 442409d
   ("update status of #35 to reflect completion") says the same, but the issue was never closed.
   Close it, or reopen the question of what's left.

4. **launch-infra's last open question is resolved.** Its 2026-07-09 log ends "final confirmation
   that `npm publish` reaches the registry successfully is still pending the next real cycle."
   It did: `@stylusnexus/agentarmor@0.2.13` published 2026-07-09T13:31Z through the automated
   path. (0.2.6–0.2.12 never reached npm — those were the stuck cycles.) That track can close,
   and CLAUDE.md's "not yet proven end-to-end" Publishing note is now wrong.

5. **#69's claims check out exactly.** `steganographic-payload` has zero patterns and zero eval
   samples — only `src/types/index.ts:25` declares it. Per-type sample counts confirmed against
   `scripts/eval/samples.ts`: 11 `oversight-evasion`, 11 `data-exfiltration`, 10
   `embedded-jailbreak` at the top; 3–4 for the five thin types the issue names.

## Session log

### Session — 2026-08-05 22:07

- Track created as a convergence track after reading all seven `.work-plan/` tracks, all 22 open
  GitHub issues, and the relevant source, then ranking the backlog by value-per-unit-effort.
- Ranking weighted toward demoable credibility because the repo is public-but-unlaunched
  (4 stars, 614 downloads/month) and the stated near-term goal is credibility, not revenue.
- Five backlog corrections found by checking live code rather than issue text. The #26 finding
  moves the ranking most: it promotes #28 from "blocked behind a taxonomy change" to "rank 1,
  low effort".
- Nothing implemented — analysis and ordering only.

### Session — 2026-08-05 22:55 (rank 1 shipped, re-ranked)

- #28 merged (PR #94, `0505bc7`), closing #26 with it. Ranking re-derived rather than appended to,
  per this track's own rule: **#71 is now rank 1**, then #69 item 1, then #68 items 1+3.
- Correction 1 is now confirmed rather than predicted — the #26 finding held up under implementation.
- Reusable output from #28 that changes later estimates: `BaseDetector.redactEvidence()` +
  `PatternDetector.maskEvidence` exist now, so #27 and #30 get secret-safe evidence for free; and
  `scripts/eval/samples.ts` has a `fake()` helper for building secret-shaped fixtures that don't
  trip push protection.
- Release PR #93 (0.2.14) carries #28 and is deliberately left unmerged — npm publish is the real
  deploy gate, and more work is batching into it first. Site already deployed and verified live.
- Decided against adding a `dev` branch (CritForge-style): CritForge's `dev` maps to a real Render
  staging deployment, agent-armor has no second environment, and release PR #93 already is the
  staging gate. Retargeting release-please — which only started working end-to-end at 0.2.13 after
  three separate bug fixes (#81, #85, #88) — is asymmetric downside for a queue that isn't needed.
  Revisit if external contributors arrive post-launch or a hosted Pro API appears.
