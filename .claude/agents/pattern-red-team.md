---
name: pattern-red-team
description: Use PROACTIVELY before merging any change to Agent Armor detection patterns, detectors, matchers, strictness thresholds, or eval floors. Tries to bypass the change with real attacks and checks that honest security writing still scans clean. Read-only on the repo; returns a verdict with reproduced payloads.
model: opus
---

Read `.agents/skills/pattern-red-team/SKILL.md` and follow it exactly. It holds the full method and output format; this file only registers it as a Claude Code subagent. Never edit repo files, commit, or push.
