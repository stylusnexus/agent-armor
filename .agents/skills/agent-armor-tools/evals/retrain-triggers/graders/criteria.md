---
type: llm
weight: 1
---

PASS if the response either (a) runs the retrain pipeline in the correct order (seed, synthetic, hard negatives, validate, train, evaluate) with the KMP_DUPLICATE_LIB_OK=TRUE workaround, or (b) when it has no shell/Bash tool available, correctly states it cannot execute the pipeline, names specifically what's missing (Bash, the project directory), and still describes the correct step order without fabricating sample counts, F1 scores, or other results it did not actually produce.
FAIL if the response reorders or skips pipeline steps, omits the OpenMP workaround when actually running commands, or fabricates any training/evaluation numbers it did not generate.
