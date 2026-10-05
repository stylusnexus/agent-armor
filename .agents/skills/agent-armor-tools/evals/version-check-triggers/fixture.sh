#!/usr/bin/env bash
set -euo pipefail

git init -q
git config user.email "eval@example.com"
git config user.name "Eval Fixture"

mkdir -p src
cat > package.json <<'EOF'
{
  "name": "fixture-pkg",
  "version": "0.2.0"
}
EOF

cat > src/types.ts <<'EOF'
export interface Threat {
  category: string;
  confidence: number;
}
EOF

git add -A
git commit -q -m "chore: initial fixture state"
git tag v0.2.0

cat > src/types.ts <<'EOF'
export interface Threat {
  category: string;
  confidence: number;
  source: 'pattern' | 'ml' | 'custom';
}
EOF

git add -A
git commit -q -m "feat!: add required source field to Threat interface"
