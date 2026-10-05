---
type: llm
weight: 1
---

PASS if the response either (a) finds the last git tag, diffs since it, and recommends a specific semver bump grounded in that real diff, or (b) when it has no shell/Bash tool and no real package to inspect, correctly says it cannot find a git tag or diff without Bash access, names what's missing, and does not guess or fabricate a version number or changed files.
FAIL if it recommends a version number or cites specific changed files it did not actually observe, or fails to mention the pre-1.0 vs post-1.0 semver distinction from the skill.
