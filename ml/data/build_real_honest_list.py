"""Build ml/data/real_honest_list.jsonl: real documents agents read (#276).

The false-flag rate of the classifier has only been measured on honest text this
repo wrote, which is small (105 samples) and shares a drafting style with the
training data. This script picks real documents from public repositories whose
license permits use (MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, CC0-1.0):
READMEs, docs, policies, agent instruction files (AGENTS.md, CLAUDE.md,
.cursorrules, SKILL.md) and MCP manifests.

It writes only the list: repository, path, the commit it was read at, the
license, the size and the SHA-256 of the text. The text itself is fetched at
evaluation time by fetch_real_honest.py and is never committed.

Selection is deterministic for a given --seed. No more than --per-repo documents
come from one repository. Search results rank by stars, so very popular and
very obscure repositories are both under-represented; the list is meant to show
the false-flag rate on ordinary documents, not to be a random sample of GitHub.

Usage (needs the `gh` CLI, logged in):
    python3 -m ml.data.build_real_honest_list --target 1000
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import subprocess
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
OUT = ROOT / "ml" / "data" / "real_honest_list.jsonl"

ALLOWED_LICENSES = {"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "CC0-1.0"}
SEARCH_LICENSES = ["mit", "apache-2.0", "bsd-3-clause", "bsd-2-clause", "cc0-1.0"]

# Topics weighted toward what agents read; the rest keep the list ordinary.
TOPICS = [
    "mcp-server", "model-context-protocol", "ai-agent", "llm", "claude-code", "langchain",
    "cli", "documentation", "web-framework", "developer-tools", "python-library", "rust",
    "golang", "typescript", "react", "docker", "kubernetes", "database", "security",
    "devops", "machine-learning", "api", "testing", "automation", "data-science",
]

MIN_BYTES, MAX_BYTES = 300, 150_000
PER_KIND_CAP = {"agent-file": 2, "readme": 2, "doc": 3, "policy": 2, "template": 1, "manifest": 1}
EXCLUDE_REPO = re.compile(r"^(stylusnexus)/", re.I)

AGENT_FILES = re.compile(
    r"(^|/)(AGENTS\.md|CLAUDE\.md|GEMINI\.md|\.cursorrules|SKILL\.md|copilot-instructions\.md)$", re.I
)
README = re.compile(r"^(packages/[^/]+/|[^/]+/)?README\.md$", re.I)
POLICY = re.compile(r"(^|/)(CONTRIBUTING|SECURITY|SUPPORT|GOVERNANCE|CODE_OF_CONDUCT)\.md$", re.I)
TEMPLATE = re.compile(r"(^|/)(\.github/)?(ISSUE_TEMPLATE/[^/]+\.md|PULL_REQUEST_TEMPLATE\.md)$", re.I)
MANIFEST = re.compile(r"(^|/)(server\.json|manifest\.json|mcp\.json)$", re.I)
DOC = re.compile(r"^docs?/.+\.(md|mdx|rst|txt)$", re.I)


def gh(path: str, *params: str) -> dict | list:
    out = subprocess.run(
        ["gh", "api", "-X", "GET", path, *params], capture_output=True, text=True, timeout=120
    )
    if out.returncode != 0:
        raise RuntimeError(out.stderr.strip()[:200])
    return json.loads(out.stdout)


def kind_of(path: str) -> str | None:
    if AGENT_FILES.search(path):
        return "agent-file"
    if README.match(path):
        return "readme"
    if POLICY.search(path):
        return "policy"
    if TEMPLATE.search(path):
        return "template"
    if MANIFEST.search(path):
        return "manifest"
    if DOC.match(path):
        return "doc"
    return None


def discover_repos(rng: random.Random, want: int) -> list[dict]:
    """Search repositories by topic and license; return a shuffled, de-duplicated list."""
    seen: dict[str, dict] = {}
    queries = [(t, lic) for t in TOPICS for lic in SEARCH_LICENSES[:3]]
    queries += [(t, lic) for t in TOPICS[:8] for lic in SEARCH_LICENSES[3:]]
    rng.shuffle(queries)
    for topic, lic in queries:
        if len(seen) >= want:
            break
        q = f"topic:{topic} license:{lic} stars:20..5000 pushed:>2025-06-01 archived:false fork:false"
        try:
            res = gh("search/repositories", "-f", f"q={q}", "-f", "per_page=30", "-f", "sort=updated")
        except RuntimeError as err:
            print(f"  search failed for {topic}/{lic}: {err}", file=sys.stderr)
            time.sleep(10)
            continue
        for r in res.get("items", []):
            spdx = (r.get("license") or {}).get("spdx_id")
            if spdx in ALLOWED_LICENSES and not EXCLUDE_REPO.match(r["full_name"]):
                seen.setdefault(r["full_name"], {"repo": r["full_name"], "license": spdx, "branch": r["default_branch"], "topic": topic})
        time.sleep(2.3)  # search API: 30 requests a minute
        print(f"  {len(seen)} repositories after {topic}/{lic}", flush=True)
    repos = list(seen.values())
    rng.shuffle(repos)
    return repos


def candidate_files(repo: dict) -> list[dict]:
    """Pin the repository at its current commit and choose its candidate documents."""
    commit = gh(f"repos/{repo['repo']}/branches/{repo['branch']}")["commit"]["sha"]
    tree = gh(f"repos/{repo['repo']}/git/trees/{commit}", "-f", "recursive=1")
    per_kind: dict[str, int] = {}
    chosen = []
    for node in sorted(tree.get("tree", []), key=lambda n: (n["path"].count("/"), n["path"])):
        if node["type"] != "blob" or not (MIN_BYTES <= node.get("size", 0) <= MAX_BYTES):
            continue
        kind = kind_of(node["path"])
        if kind is None or per_kind.get(kind, 0) >= PER_KIND_CAP[kind]:
            continue
        per_kind[kind] = per_kind.get(kind, 0) + 1
        chosen.append({**repo, "commit": commit, "path": node["path"], "kind": kind, "bytes": node["size"]})
    return chosen


def read_text(item: dict) -> str | None:
    url = f"https://raw.githubusercontent.com/{item['repo']}/{item['commit']}/{item['path']}"
    try:
        with urllib.request.urlopen(url, timeout=30) as r:
            raw = r.read()
        text = raw.decode("utf-8")
    except Exception:
        return None
    return text if len(text.strip()) >= MIN_BYTES // 2 else None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", type=int, default=1000, help="documents to collect")
    ap.add_argument("--per-repo", type=int, default=6)
    ap.add_argument("--seed", type=int, default=276)
    args = ap.parse_args()
    rng = random.Random(args.seed)

    print("Searching repositories ...")
    repos = discover_repos(rng, want=max(args.target // 2, 200))
    print(f"{len(repos)} candidate repositories")

    docs: list[dict] = []
    used_repos = 0
    for i, repo in enumerate(repos):
        if len(docs) >= args.target:
            break
        try:
            files = candidate_files(repo)[: args.per_repo]
        except RuntimeError as err:
            print(f"  skip {repo['repo']}: {err}", file=sys.stderr)
            continue
        with ThreadPoolExecutor(max_workers=8) as pool:
            texts = list(pool.map(read_text, files))
        got = 0
        for f, text in zip(files, texts):
            if text is None or len(docs) >= args.target:
                continue
            docs.append(
                {
                    "repo": f["repo"], "path": f["path"], "commit": f["commit"], "license": f["license"],
                    "kind": f["kind"], "bytes": len(text.encode("utf-8")),
                    "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                }
            )
            got += 1
        used_repos += 1 if got else 0
        if i % 20 == 0:
            print(f"  {len(docs)} documents from {used_repos} repositories", flush=True)

    docs.sort(key=lambda d: (d["repo"], d["path"]))
    OUT.write_text("".join(json.dumps(d) + "\n" for d in docs), encoding="utf-8")
    kinds: dict[str, int] = {}
    for d in docs:
        kinds[d["kind"]] = kinds.get(d["kind"], 0) + 1
    print(f"Wrote {len(docs)} documents from {len({d['repo'] for d in docs})} repositories to {OUT.relative_to(ROOT)}")
    print(f"By kind: {kinds}")
    print("By license:", {l: sum(1 for d in docs if d['license'] == l) for l in sorted({d['license'] for d in docs})})


if __name__ == "__main__":
    main()
