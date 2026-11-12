# PR: fix(api1): enforce authentication and object-level authorization on /api/dashboard

Branch: `fix/task2-bola-authorization` -> `main`  |  Diff: [`TASK2_PR.diff`](TASK2_PR.diff)  |  Finding: Task 1 report

## Problem
`GET /api/dashboard?appId=` looked up a record by a caller-supplied id only: no login, no ownership check, whole record returned, error text echoed the input.

## Change
Handler order in `src/routes/dashboard.ts`:

| Step | Control | Result on failure |
|---|---|---|
| 1 | Sliding-window throttle (30 req/min/IP) | 429 + `Retry-After` |
| 2 | Identity from the signed, unexpired, unrevoked session cookie only | 401 |
| 3 | `appId` must match `^DT-\d{4}-\dgit switch main
git pull
{3}$` | 404 |
| 4 | Query by `appId` **and** session owner (`findByAppIdForOwner`) | 404 (same body as a missing record) |
| 5 | Return only `appId, name, email, phone, notes` | - |

Unexpected errors are caught in the router and return `{"error":"Internal server error"}`; nothing about the database or stack is exposed.

## Why 404 and not 403 for someone else's record
403 confirms the record exists, which helps an attacker enumerate. 404 for both cases removes that signal.

## Tests added (`tests/task2-bola.test.ts`)
- No session -> 401, no personal data
- Owner reads own record; only intended fields returned
- **User A cannot read User B (and the reverse)**; response is identical to a nonexistent id
- SQL-injection-style, traversal and null-byte ids rejected generically
- `alg:none`, edited-payload, wrong-secret and expired tokens -> 401
- Simulated database failure -> generic 500, no internals
- 40 unauthenticated enumeration requests -> 30 x 401 then 10 x 429

## How to verify
```bash
npm test                      # 33 tests
npm start & npx tsx poc/idor_probe.ts http://127.0.0.1:3000 /api/dashboard   # 0 of 10 ids returned data
```

## Next.js note
Handlers are `(Request) => Promise<Response>`, the same shape as App Router route handlers. In Next.js, create `app/api/dashboard/route.ts` with `export const GET = dashboardHandler(deps);`.
