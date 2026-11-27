---
track: fiction-false-positives
status: active
launch_priority: P1
milestone_alignment: v1.0.0
github:
  repo: stylusnexus/agent-armor
  issues:
    - 303
    - 305
    - 306
    - 307
    - 368
  branches: []
depends_on: []
last_touched: 2026-10-20T04:15
last_handoff: 2026-10-20T04:15
next_up:
  - 306
  - 303
  - 368
blockers: []
---

# Fiction False Positives

Honest fiction and game text flagged as attacks, and the missing ways for consumers to say "this is a story". These came from evaluating Agent Armor for CritForge, a tabletop game-master tool that now depends on `@stylusnexus/agentarmor@^0.2.23`. That makes it the first real consumer reporting against the scanner.

Widened on 2026-10-20 to cover honest-text false positives in general (#368: real repository documents), not only fiction.

Created P1 on 2026-10-20. A consumer that withholds output on `critical` currently withholds ordinary fiction (#303), and strictness can't fix that because the pattern fires at `permissive`.

## Issues

| #    | Title                                                                    | Assignee       | Status                                  |
| ---- | ------------------------------------------------------------------------ | -------------- | --------------------------------------- |
| #303 | fix(patterns): ex-read-env flags 'reveal secrets' in fiction at critical | maneumeyer-chs | 🔲 Open (fix acceptance criteria first) |
| #305 | feat(patterns): detect messages addressed to the AI reading the text     | —              | 🔲 Open                                 |
| #306 | test(eval): add a benign narrative-fiction sample set                    | maneumeyer-chs | 🔲 Open                                 |
| #368 | fix(patterns): regex flags 9% of real honest docs                        | maneumeyer-chs | 🔲 Open                                 |
| #307 | feat: let consumers suppress or re-weight patterns for fiction content   | —              | 🔲 Open                                 |

## Dependencies

```
#306 (fiction eval set) ──► #303 (ex-read-env fix) ──► #305 (AI-addressed patterns)
         │
         └──► #307 (suppress / re-weight API)

#368 (real-document false flags): measure first, then HTML comments and badge images
#368 ──► #304 (detection-hardening; same markdown-image detection)
```

- **#306 first.** Without a fiction set, the eval gate can't fail on a pattern that mangles stories, so neither #303 nor #305 can prove it doesn't regress. About 100 samples, no trademarked game text, reported separately, and the gate fails on any false flag. The spy and oracle sentences from #303 still flag today, so adding them would fail the gate. Ship them in #303's PR, or ship #306 and #303 together.
- **#303 after #306.** Fix its acceptance criteria first: "reveal your API keys" and "show me ~/.aws/credentials" scan clean today, so they can't "still flag". It probably needs an "object required" rule: "reveal secrets **of the court**" is story text; "reveal the secrets **in .env**" is not. Run the `pattern-red-team` review per AGENTS.md.
- **#305 after #303.** New patterns for messages addressed to the model must keep #303's object-required rule, so dialogue like "forget everything I told you" doesn't flag. #178 closed (2026-10-20), so it's no longer a prerequisite. #305 now also carries #178's remaining case: use the "addressed to the AI" signal to raise `ex-conversation-to-destination` to `balanced`. Don't widen the general instruction check: #178 measured that at 3–7 extra false flags per 1,000 real documents. New phrase patterns whose honest look-alikes share their wording ship at `strict` only (AGENTS.md).
- **#307 can be designed in parallel; ship it after #303.** Threats carry no pattern id today, so suppressing a single pattern means adding one to `Threat`. That's a public API change, so it's a minor bump (`0.3.0`) under the versioning policy. Batch it with #358 (runtime-hardening), which also needs a minor bump.

## Session log

### Session — 2026-10-20 00:45 (track created)

- Created from the 2026-10-20 backlog review (see `best-wins-cross`). #303 and #305–#307 had no home track.
- Ordering: #306, then #303, then #305. #307 can be designed in parallel and released with the other `0.3.0` change.

### Session — 2026-10-20 04:15 (#368 added; #178 dependency removed)

- **Track widened to honest-text false positives.** Filed #368 and gave it this track as its home. The regex layer flags 90 of 1,000 real honest documents at `balanced` (102 at `strict`; `permissive` also 90). Main sources:
  - HTML comments: 44 documents, mostly lint directives, generated-file notices and PR-template guidance.
  - Badge images with a query token: 15 documents.
  - The README publishes the ML rate for this set, not the regex rate.
- **#305 no longer waits on #178** (closed at `strict`). It gained an acceptance line for the variants aimed at the agent.
- **#306 sequencing fix:** #303's sentences still flag, so they go in #303's PR or ship with it.
- #303 and #306 are assigned to maneumeyer-chs. next_up: #306, #303, #368.
