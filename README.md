# Datheon_AppSec_Internship

IDOR discovery, BOLA remediation and secure session handling, built as a runnable lab: a deliberately flawed endpoint, the exploit that proves it, the hardened replacement, and the evidence.

> **Responsible use.** The vulnerable route is mounted only outside production and binds to `127.0.0.1`. All data is fictional. Test only systems you own or have written permission to test.

## Tasks completed (4 of 4)

| Task | Deliverable | Where |
|---|---|---|
| **1. Black-box recon and IDOR discovery** | Disclosure report with cURL reproduction and CVSS 3.1 calculation (7.5 High) | [`reports/TASK1_VULNERABILITY_DISCLOSURE_REPORT.md`](reports/TASK1_VULNERABILITY_DISCLOSURE_REPORT.md), `poc/idor_probe.ts`, `scripts/curl_repro.sh` |
| **2. BOLA remediation** | Hardened route, 13 integration tests, PR diff | `src/routes/dashboard.ts`, `tests/task2-bola.test.ts`, [`docs/TASK2_PR.diff`](docs/TASK2_PR.diff), [`docs/TASK2_PR_DESCRIPTION.md`](docs/TASK2_PR_DESCRIPTION.md) |
| **3. Session security** | HttpOnly signed cookies, rotation, expiry, sliding-window rate limiter with live demo | `src/lib/*`, `src/routes/auth.ts`, `tests/task3-session.test.ts`, [`docs/TASK3_SESSION_SECURITY.md`](docs/TASK3_SESSION_SECURITY.md) |
| **4. Public endpoint shielding, PII masking, DAST** | Masked public verify API, security headers on every response, gitleaks + Spectral + ZAP workflow | `src/lib/mask.ts`, `src/routes/publicVerify.ts`, `src/lib/securityHeaders.ts`, `tests/task4-public.test.ts`, `.github/workflows/security.yml`, [`docs/TASK4_PUBLIC_API_HARDENING.md`](docs/TASK4_PUBLIC_API_HARDENING.md) |

## Architecture

```
 browser / curl / poc script
          |  HTTP
   src/server.ts            thin Node adapter: http -> Web Request, stamps trusted client IP
          |
   src/router.ts            (Request) => Promise<Response>, same shape as Next.js route handlers
     |        |         \
 routes/    routes/     lab/vulnerableDashboard.ts   (Task 1 target, off in production)
 auth.ts    dashboard.ts (hardened)   publicVerify.ts (masked, public)
     \        |
      lib/ jwt (HS256) - session (cookies) - rateLimit (sliding window) - tokenStore (revocation)
            password (scrypt) - db (in-memory, fictional) - http (safe errors)
            mask (PII masking) - securityHeaders (applied to every response)
```

Hardened request path: **throttle -> authenticate (signed cookie) -> validate id -> query by id AND owner -> minimal response**. There are no runtime dependencies; only Node 20+ built-ins (`node:crypto`, `node:http`, `node:test`).

## Run it

```bash
npm install
npm test                 # 50 tests
npm start                # http://127.0.0.1:3000  (vulnerable lab route ON in dev)

# Task 1: open the lab dashboard page in a browser, watch the fetch in DevTools, then exploit it
#   http://127.0.0.1:3000/lab/dashboard?appId=DT-2026-001
./scripts/curl_repro.sh
npx tsx poc/idor_probe.ts http://127.0.0.1:3000 /api/vulnerable/dashboard   # exit 1 = vulnerable

# Task 2: same probe against the fixed route
npx tsx poc/idor_probe.ts http://127.0.0.1:3000 /api/dashboard               # exit 0, all 401
```

Lab accounts: `alice@example.com / Alice#Lab-2026` (owns DT-2026-001), `bob@example.com / Bob#Lab-2026!` (owns DT-2026-002).

Production: set `NODE_ENV=production` and a `JWT_SECRET` of 32+ characters (the app refuses to start otherwise). This enables `Secure` cookies with the `__Host-` prefix and removes the vulnerable lab route.

## Git history for the Task 2 pull request

```bash
./scripts/make_git_history.sh          # fresh copy only; uses your git identity
git push -u origin main fix/task2-bola-authorization    # then open the PR on GitHub
```

`main` holds the vulnerable baseline (20 tests pass); the branch adds the fix and Task 2 tests (33 pass).

## Results

| Check | Before | After |
|---|---|---|
| Dashboard with no cookie | 200 + PII (`reports/evidence/task1_probe_vulnerable.txt`) | 401 |
| Alice requests Bob's record | n/a (anyone could) | 404, identical to a missing id |
| Forged `alg:none` / edited / expired token | n/a | 401 |
| 6th login attempt in a minute | n/a | 429 + `Retry-After` |
| Replay of a token after refresh or logout | n/a | 401 |
| Public verify response | n/a | masked name/email/phone only (`a***e@example.com`) |
| Security headers on 401/404/405/500 | partial | CSP, HSTS, nosniff, X-Frame-Options, Referrer-Policy, Permissions-Policy on all |

## Honest notes
- Tests use Node's built-in runner (`node:test`) with Vitest-style `describe/it`; porting to Vitest/Jest is an import change only.
- The Task 4 GitHub Actions workflow (`security.yml`) has not run on GitHub yet; the tests and header gate were run locally.
- `npm run typecheck` was **not** run in my build environment (no `@types/node` offline). Run it once locally before pushing; the CI workflow runs it.
- The rate limiter and revocation list are in memory. For multiple instances, back them with Redis (see `docs/TASK3_SESSION_SECURITY.md`).
- Task 1 was performed on this local lab. If Datheon assigned a specific in-scope application, apply the same method there with permission and update the report.
