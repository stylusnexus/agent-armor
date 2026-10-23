---
track: runtime-hardening
status: active
launch_priority: P1
milestone_alignment: v1.0.0
github:
  repo: stylusnexus/agent-armor
  issues:
    - 274
    - 358
    - 359
    - 360
  references:
    - 37
  branches: []
depends_on: []
last_touched: 2026-10-20T04:15
last_handoff: 2026-10-20T04:15
next_up:
  - 358
  - 274
blockers: []
---

# Runtime Hardening

How the CLI and the ML package behave at runtime: exit codes that gate CI, model loading and integrity checks, and how much of a document the ML layer actually reads.

Created P1 on 2026-10-20. Most issues here came out of the review of the 0.2.26 promotion (#345), which shipped CLI changes (#343) and ML artifact verification (#344).

## Issues

| #    | Title                                                              | Assignee       | Status                                        |
| ---- | ------------------------------------------------------------------ | -------------- | --------------------------------------------- |
| #274 | fix(ml): long documents are scanned only up to token 510           | —              | 🔲 Open                                       |
| #358 | fix(cli): fail closed on missing scan paths by default             | —              | 🔲 Open                                       |
| #359 | fix(ml): bad modelChecksums downloads the model on every start     | maneumeyer-chs | 🟡 Merged to `dev` (#366); ships in ML 0.1.11 |
| #360 | docs(ml): document AGENTARMOR_MODEL_DIR and custom-model checksums | maneumeyer-chs | 🟡 Merged to `dev` (#367); ships in ML 0.1.11 |

## Dependencies

- **#359 first.** It's a small fix: check the checksum shape before any I/O, and narrow the cache-miss `catch`. The bug costs a ~165MB download on every start. Ships as an ML patch release.
- **#360 with #359.** Both concern the same rule: custom model directories need all three checksums. Document it in the same ML release.
- **#358 is a behavior change.** Changing the CLI default to exit `2` on a missing path is a minor bump (`0.3.0`) under the versioning policy. Batch it with #307 (fiction-false-positives), the other change that needs a minor bump.
- **#274 needs a long-document eval set.** The current training and eval data is almost entirely under 512 tokens, so neither head-and-tail truncation nor sliding windows can be measured yet. Build the set once and share it with #37 (detection-hardening, attention dilution), which needs the same long documents.

## Design notes

- **Hashing the model at startup is intentional.** On every cache hit, `validateModelDir` re-hashes the ONNX model, tokenizer and label map with SHA-256. That costs time at every start, including serverless cold starts. AGENTS.md says "never reuse a cache without verification", so a size or mtime marker that skips the hash would break that rule. Only revisit it by changing the rule on purpose, for example by verifying once per process and hardening the cache directory's permissions.

## Session log

### Session — 2026-10-20 00:45 (track created)

- Created from the 2026-10-20 backlog review (see `best-wins-cross`). Filed #358, #359 and #360 from the #345 review; #274 had no home track.
- Two #345 review findings were not filed as bugs, because AGENTS.md defines that behavior. Re-hashing at startup is recorded above. "A custom model set by env var is rejected" became the docs issue #360.

### Session — 2026-10-20 04:15 (#359 and #360 merged to dev)

- **#366 (#359):**
  - Checks the checksum shape before any file or network I/O.
  - Counts only `MODEL_NOT_FOUND`, `CHECKSUM_MISMATCH` and `ENOENT` as a cache miss. This covers both cache checks, including the one after waiting on another process's lock, which the issue didn't mention.
  - An unreadable cache now reports its real error instead of being downloaded over.
- **#367 (#360):** documents `AGENTARMOR_MODEL_DIR` and the model-check error codes. The optional `AGENTARMOR_MODEL_CHECKSUMS` variable is left as a separate decision.
- Both issues close when `dev` is promoted to `main`. They're ready for the ML 0.1.11 release PR.
- next_up: #358 (build now, merge with #307 for 0.3.0), #274.
