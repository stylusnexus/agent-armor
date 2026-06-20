# .work-plan/

This folder contains **shared planning tracks** managed by [`work-plan`](https://github.com/stylusnexus/work-plan-toolkit).

Each `.md` file is a planning track: a lightweight document with YAML frontmatter that
points at GitHub issues and captures session notes. GitHub is canonical for issue state;
these files are the *planning context* that travels with the code.

## Shared vs. private tracks

Tracks in this folder are the **shared tier** — they're committed and sync via `git pull`.
To keep a track private (personal notes, not for teammates), use `--private` when creating
it and it will go into your local `notes_root` folder instead.

## Setup

Install the toolkit: [stylusnexus/work-plan-toolkit](https://github.com/stylusnexus/work-plan-toolkit)
Also available as a Claude/Codex plugin: [stylusnexus/agent-plugins](https://github.com/stylusnexus/agent-plugins)
