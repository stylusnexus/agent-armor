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
  references:
    - 178
  branches: []
depends_on:
  - detection-hardening
last_touched: 2026-10-20T00:45
last_handoff: 2026-10-20T00:45
next_up:
  - 306
  - 303
blockers: []
---

# Fiction False Positives

Honest fiction and game text flagged as attacks, and the missing ways for consumers to say "this is a story". These came from evaluating Agent Armor for CritForge, a tabletop game-master tool that now depends on `@stylusnexus/agentarmor@^0.2.23`. That makes it the first real consumer reporting against the scanner.

Created P1 on 2026-10-20. A consumer that withholds output on `critical` currently withholds ordinary fiction (#303), and strictness can't fix that because the pattern fires at `permissive`.

## Issues

| #    | Title                                                                    | Assignee | Status  |
| ---- | ------------------------------------------------------------------------ | -------- | ------- |
| #303 | fix(patterns): ex-read-env flags 'reveal secrets' in fiction at critical | —        | 🔲 Open |
| #305 | feat(patterns): detect messages addressed to the AI reading the text     | —        | 🔲 Open |
| #306 | test(eval): add a benign narrative-fiction sample set                    | —        | 🔲 Open |
| #307 | feat: let consumers suppress or re-weight patterns for fiction content   | —        | 🔲 Open |

## Dependencies

```
#306 (fiction eval set) ──► #303 (ex-read-env fix) ──► #305 (AI-addressed patterns)
         │                                                ▲
         └──► #307 (suppress / re-weight API)    #178 ────┘ (detection-hardening)
```

- **#306 first.** Without a fiction set, the eval gate can't fail on a pattern that mangles stories, so neither #303 nor #305 can prove it doesn't regress. About 100 samples, no trademarked game text, reported separately, and the gate fails on any false flag. Include the spy and oracle sentences from #303.
- **#303 after #306.** It probably needs an "object required" rule: "reveal secrets **of the court**" is story text; "reveal the secrets **in .env**" is not. Run the `pattern-red-team` review per AGENTS.md.
- **#305 after #303 and #178.** New patterns for messages addressed to the model must keep #303's object-required rule, so dialogue like "forget everything I told you" doesn't flag. #178 (detection-hardening) changes the same instruction-signal check, so finish it first. New phrase patterns whose honest look-alikes share their wording ship at `strict` only (AGENTS.md).
- **#307 can be designed in parallel; ship it after #303.** Threats carry no pattern id today, so suppressing a single pattern means adding one to `Threat`. That's a public API change, so it's a minor bump (`0.3.0`) under the versioning policy. Batch it with #358 (runtime-hardening), which also needs a minor bump.

## Session log

### Session — 2026-10-20 00:45 (track created)

- Created from the 2026-10-20 backlog review (see `best-wins-cross`). #303 and #305–#307 had no home track.
- Ordering: #306, then #303, then #305. #307 can be designed in parallel and released with the other `0.3.0` change.
