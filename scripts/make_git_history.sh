#!/usr/bin/env bash
# Builds a realistic history for the Task 2 pull request, using YOUR git identity:
#   main                          baseline: blind lookup in /api/dashboard (the Task 1 finding)
#   fix/task2-bola-authorization  hardened handler + integration tests (open this as the PR)
# Run once in a fresh copy of the project (no .git yet).
set -euo pipefail
cd "$(dirname "$0")/.."
[ -e .git ] && { echo "A .git directory already exists - run this in a fresh copy."; exit 1; }

tmp="$(mktemp -d)"
cp src/routes/dashboard.ts "$tmp/dashboard.final.ts"
cp tests/task2-bola.test.ts "$tmp/task2-bola.test.ts"

git init -q -b main
cp scripts/baseline/dashboard.ts src/routes/dashboard.ts   # vulnerable baseline
rm tests/task2-bola.test.ts
git add -A
git commit -q -m "feat: lab API with cookie sessions, rate limiting and an unauthenticated dashboard lookup (baseline)"

git switch -q -c fix/task2-bola-authorization
cp "$tmp/dashboard.final.ts" src/routes/dashboard.ts
cp "$tmp/task2-bola.test.ts" tests/task2-bola.test.ts
git add -A
git commit -q -m "fix(api1): enforce authentication and object-level authorization on /api/dashboard

- 401 without a valid signed session cookie
- query by appId AND session owner; foreign or unknown ids return the same 404
- strict appId format validation, lookup throttling, minimal response fields
- integration tests: User A cannot read User B, forged/expired tokens, no error leakage"

git switch -q main
echo "Done. Next:"
echo "  git remote add origin https://github.com/<you>/Datheon_AppSec_Internship.git"
echo "  git push -u origin main fix/task2-bola-authorization"
echo "  then open a pull request: fix/task2-bola-authorization -> main"
