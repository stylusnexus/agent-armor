#!/usr/bin/env bash
# Delete remote branches whose work has landed.
#
# Dry run by default: prints what it would delete and what it keeps, and why.
# Pass --apply to delete.
#
# A branch is deleted only when one of these holds:
#   - its newest PR was merged and the branch tip is still that PR's head
#     (nothing was pushed after the merge), or
#   - its tip is already in origin/dev or origin/main.
# With --include-closed, branches whose newest PR was closed without merging
# are deleted too (same tip check). Everything else is kept: open PRs, branches
# with no PR, commits pushed after a merge, main, dev, release-please branches
# and any branch GitHub protects.
#
# Needs git, gh (authenticated) and a clone whose remote is the repo.
# Runs on bash 3.2 (macOS) and GNU bash.
set -euo pipefail

REMOTE=origin
APPLY=0
INCLUDE_CLOSED=0
MIN_AGE_DAYS=0

usage() {
  cat <<'EOF'
Usage: scripts/cleanup-remote-branches.sh [--apply] [--include-closed] [--min-age-days N] [--remote NAME]

  --apply            delete the branches (default: dry run)
  --include-closed   also delete branches whose newest PR was closed unmerged
  --min-age-days N   keep branches whose last commit is newer than N days (default 0)
  --remote NAME      remote to clean (default: origin)
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --apply) APPLY=1 ;;
    --include-closed) INCLUDE_CLOSED=1 ;;
    --min-age-days) MIN_AGE_DAYS="${2:?--min-age-days needs a number}"; shift ;;
    --remote) REMOTE="${2:?--remote needs a name}"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

case "$MIN_AGE_DAYS" in
  ''|*[!0-9]*) echo "--min-age-days must be a whole number" >&2; exit 2 ;;
esac

command -v gh >/dev/null || { echo "gh is required" >&2; exit 1; }

url=$(git remote get-url "$REMOTE")
repo=$(printf '%s\n' "$url" | sed -E 's#^(git@[^:]+:|ssh://git@[^/]+/|https://[^/]+/)##; s#\.git$##')

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "Fetching $REMOTE ($repo)..."
git fetch --prune --quiet "$REMOTE"

# Newest PR first, so the first match per branch is its latest PR.
gh pr list --repo "$repo" --state all --limit 2000 \
  --json number,headRefName,headRefOid,state,isCrossRepository,createdAt \
  --jq 'sort_by(.createdAt) | reverse | .[] | select(.isCrossRepository | not)
        | [.headRefName, .number, .state, .headRefOid] | @tsv' >"$tmp/prs.tsv"

gh api "repos/$repo/branches?protected=true" --paginate --jq '.[].name' >"$tmp/protected.txt"

now=$(date +%s)
min_age_secs=$((MIN_AGE_DAYS * 86400))
: >"$tmp/delete.txt"

keep() { printf '  keep    %-58s %s\n' "$1" "$2"; }
# Prints the tip so a deleted branch can be pushed back from it.
drop() { printf '  delete  %-58s %s  %s\n' "$1" "${tip:0:9}" "$2"; echo "$1" >>"$tmp/delete.txt"; }

git for-each-ref --format='%(refname:lstrip=3) %(objectname) %(committerdate:unix)' \
  "refs/remotes/$REMOTE" >"$tmp/branches.txt"

while read -r branch tip when; do
  case "$branch" in
    HEAD|main|dev|release-please--*) keep "$branch" "release or long-lived branch"; continue ;;
  esac
  if grep -qxF "$branch" "$tmp/protected.txt"; then
    keep "$branch" "protected on GitHub"; continue
  fi
  if awk -F'\t' -v b="$branch" '$1==b && $3=="OPEN"{f=1} END{exit !f}' "$tmp/prs.tsv"; then
    keep "$branch" "open PR #$(awk -F'\t' -v b="$branch" '$1==b && $3=="OPEN"{print $2; exit}' "$tmp/prs.tsv")"
    continue
  fi
  if [ $((now - when)) -lt "$min_age_secs" ]; then
    keep "$branch" "last commit under $MIN_AGE_DAYS days old"; continue
  fi

  line=$(awk -F'\t' -v b="$branch" '$1==b{print; exit}' "$tmp/prs.tsv")
  if [ -n "$line" ]; then
    num=$(printf '%s' "$line" | cut -f2)
    state=$(printf '%s' "$line" | cut -f3)
    head=$(printf '%s' "$line" | cut -f4)
    if [ "$tip" != "$head" ]; then
      keep "$branch" "pushed after PR #$num ($state)"; continue
    fi
    if [ "$state" = MERGED ]; then
      drop "$branch" "PR #$num merged"; continue
    fi
    if [ "$state" = CLOSED ] && [ "$INCLUDE_CLOSED" = 1 ]; then
      drop "$branch" "PR #$num closed unmerged (--include-closed)"; continue
    fi
  fi

  if git merge-base --is-ancestor "$tip" "$REMOTE/dev" 2>/dev/null ||
     git merge-base --is-ancestor "$tip" "$REMOTE/main" 2>/dev/null; then
    drop "$branch" "already in dev or main"; continue
  fi

  if [ -n "$line" ]; then
    keep "$branch" "PR #$num closed unmerged"
  else
    keep "$branch" "no PR and not in dev or main"
  fi
done <"$tmp/branches.txt"

count=$(wc -l <"$tmp/delete.txt" | tr -d ' ')
echo
if [ "$count" = 0 ]; then
  echo "Nothing to delete."
  exit 0
fi
if [ "$APPLY" != 1 ]; then
  echo "Dry run: $count branch(es) would be deleted. Re-run with --apply to delete them."
  exit 0
fi

echo "Deleting $count branch(es) from $REMOTE..."
# Batches keep each push small; every deleted branch can be restored from its
# PR page ("Restore branch") or from the tip printed above.
xargs -n 25 git push --quiet "$REMOTE" --delete <"$tmp/delete.txt"
echo "Done."
