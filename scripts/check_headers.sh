#!/usr/bin/env bash
# Fails (exit 1) if any required security header is missing from any checked endpoint.
# Usage: scripts/check_headers.sh [base-url]     (default http://127.0.0.1:3000)
set -u
BASE="${1:-http://127.0.0.1:3000}"
REQUIRED=("content-security-policy" "strict-transport-security" "x-content-type-options: nosniff" "x-frame-options: deny" "referrer-policy" "permissions-policy")
PATHS=("/api/health" "/api/public/verify?certId=DT-CERT-7F3K9Q2M" "/api/public/verify?certId=nope" "/api/dashboard" "/no-such-route")
fail=0
for p in "${PATHS[@]}"; do
  headers="$(curl -s -o /dev/null -D - "$BASE$p" | tr -d '\r' | tr 'A-Z' 'a-z')"
  for h in "${REQUIRED[@]}"; do
    if ! grep -q "^$h" <<<"$headers"; then echo "FAIL  $p  missing: $h"; fail=1; fi
  done
  grep -q "^server:\|^x-powered-by:" <<<"$headers" && { echo "FAIL  $p  leaks server/x-powered-by"; fail=1; }
  [ $fail -eq 0 ] && echo "ok    $p"
done
exit $fail
