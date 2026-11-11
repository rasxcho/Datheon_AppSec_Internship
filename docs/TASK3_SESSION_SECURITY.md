# Task 3 - Session security design

## Why not localStorage / sessionStorage
Any JavaScript on the page can read them. A single XSS bug (a vulnerable dependency, an unsanitized field, a compromised third-party script) lets an attacker copy the token and use it from anywhere until it expires. An `HttpOnly` cookie cannot be read by script, so XSS can still make requests *as* the user but cannot exfiltrate the credential for later use.

## Implementation map
| Requirement | Where | How |
|---|---|---|
| Signed token | `src/lib/jwt.ts` | HMAC-SHA256 via `node:crypto`; algorithm pinned to HS256 (blocks `alg:none` and algorithm confusion); constant-time signature compare; strict claim checks |
| HttpOnly + SameSite cookie | `src/lib/session.ts` | `HttpOnly; SameSite=Lax; Path=/; Max-Age=900`, plus `Secure` and the `__Host-` prefix in production |
| Token only in cookie | `src/routes/auth.ts` | Login JSON body never contains the token |
| Expiry | `src/lib/config.ts` | 15-minute access token, checked on every request |
| Rotation | `POST /api/auth/refresh` | Issues a new token (new `jti`) and revokes the old one, so a replayed copy fails |
| Logout | `POST /api/auth/logout` | Server-side revocation plus cookie clearing (`Max-Age=0`) |
| Rate limiting | `src/lib/rateLimit.ts` | Sliding-window counter; login 5/min/IP, record lookups 30/min/IP; `X-RateLimit-Limit/Remaining/Reset` and `Retry-After` |
| Password storage | `src/lib/password.ts` | scrypt with per-password salt; dummy hash for unknown users (no timing oracle) |
| Secret handling | `src/lib/config.ts` | `JWT_SECRET` (>= 32 chars) required in production; random per-start key in development; never committed |

## Try it
```bash
npm start
curl -i -c jar.txt -X POST http://127.0.0.1:3000/api/auth/login -H 'content-type: application/json' \
     -d '{"email":"alice@example.com","password":"Alice#Lab-2026"}'
curl -b jar.txt http://127.0.0.1:3000/api/auth/me
curl -b jar.txt -c jar.txt -X POST http://127.0.0.1:3000/api/auth/refresh
for i in 1 2 3 4 5 6; do curl -s -o /dev/null -w "%{http_code}\n" -X POST http://127.0.0.1:3000/api/auth/login \
     -H 'content-type: application/json' -d '{"email":"bob@example.com","password":"wrong"}'; done   # ...401 x5 then 429
```
Captured output: `reports/evidence/task2_task3_live_demo.txt`.

## Known limits (be upfront about these in your write-up)
- **In-memory state** (rate limiter, revocation list) is lost on restart and not shared across instances. In production, back both with Redis (e.g. Upstash): sorted sets for the sliding window, keys with TTL for revoked `jti`s.
- **Client IP** comes from the socket. Behind a reverse proxy, use the proxy's trusted header and strip client-supplied copies.
- **CSRF:** `SameSite=Lax` blocks cross-site POSTs in modern browsers; add CSRF tokens or an `Origin` check for stronger guarantees.
- **Per-IP limits** do not stop distributed guessing; add per-account throttling with care (it can enable lockout abuse) and alerting.
- Demo users are hard-coded fictional accounts; a real system needs a user store, password policy and MFA.
