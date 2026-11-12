# Task 4: Public endpoint shielding, PII masking and automated DAST

## What was built

| Requirement | Implementation | Proof |
|---|---|---|
| Public lookup without PII | `GET /api/public/verify?certId=...` (`src/routes/publicVerify.ts`) | `tests/task4-public.test.ts` |
| Email masking (`j***e@domain.com`) | `maskEmail` in `src/lib/mask.ts` | unit tests |
| Phone masking | `maskPhone`: all digits hidden except the last two | unit tests |
| Name masking | `maskName`: initial plus `***` per word | unit tests |
| Strict security headers | `src/lib/securityHeaders.ts`, applied to every response by the router | header tests, `scripts/check_headers.sh` |
| Automated scanning in CI | `.github/workflows/security.yml` (gitleaks, Spectral, header gate, OWASP ZAP API scan) | workflow run on every push and PR |

## Public endpoint design (why it leaks nothing useful)

1. **Allow-list output.** Fields are copied one at a time. A column added to the table later cannot leak by accident.
2. **Masked PII.** A verifier who already holds the certificate can confirm "that looks like my email"; a scraper cannot recover the address, number or surname.
3. **No internal ids.** `appId` and `ownerEmail` are never returned, and `certId` does not accept `DT-2026-001`-style ids, so the public route cannot be used to enumerate applicants.
4. **No existence oracle.** Unknown and malformed ids return the same `404` body.
5. **Revoked certificates** return `{ valid: false, status: "revoked" }` and no holder details.
6. **Throttling.** 30 lookups per minute per IP in a separate bucket (`public:`), with `X-RateLimit-*` and `Retry-After`. Public responses are cacheable for 60 s; errors are `no-store`.

Example response:

```json
{"valid":true,"certificateId":"DT-CERT-7F3K9Q2M","status":"issued","program":"Application Security Internship","issuedOn":"2026-10-01","holder":"A*** K***","email":"a***e@example.com","phone":"+** ***** ***01"}
```

Further data minimisation: if verifiers do not need the phone number at all, delete that one line in `publicVerify.ts`. The best way to protect a field is not to return it.

## Security headers

| Header | Value | Stops |
|---|---|---|
| Content-Security-Policy | `default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'` | Script/content injection into responses, clickjacking |
| Strict-Transport-Security | `max-age=63072000; includeSubDomains; preload` | Downgrade and SSL-strip attacks (ignored over plain http, so harmless locally) |
| X-Content-Type-Options | `nosniff` | MIME sniffing |
| X-Frame-Options | `DENY` | Clickjacking in older browsers |
| Referrer-Policy | `no-referrer` | URL leakage (ids in query strings) via the Referer header |
| Permissions-Policy | camera, microphone, geolocation, payment off | Browser feature abuse |
| Cross-Origin-Resource-Policy / Opener-Policy | `same-origin` | Cross-site reads and window handle attacks |

The router applies these in one place, so 401, 404, 405 and 500 responses carry them too. The HTML dashboard page keeps its own nonce-based CSP (the router only fills in missing headers). For Next.js, see `docs/next.config.example.ts`.

## CI/CD pipeline (`.github/workflows/security.yml`)

- **gitleaks** scans the full git history for committed secrets.
- **Spectral** lints `openapi.yaml` (operation ids, tags, servers); errors fail the build.
- **Header gate** (`scripts/check_headers.sh`): starts the API, then fails if any required header is missing on five representative endpoints, error responses included, or if `Server` / `X-Powered-By` leak.
- **OWASP ZAP API scan** runs `zap-api-scan.py` against the live API using the OpenAPI file, uploads the HTML report, and fails on ZAP FAIL-level findings. Rule overrides live in `.zap/rules.tsv`.

The existing `ci.yml` still runs typecheck and the 50 tests.

## Verify it locally

```powershell
npm test                                   # 50 tests
npm start                                  # in one terminal
curl.exe -s -i "http://127.0.0.1:3000/api/public/verify?certId=DT-CERT-7F3K9Q2M"
bash scripts/check_headers.sh              # Git Bash / WSL; prints "ok" per endpoint
```

## Honest notes
- The workflow file has not run on GitHub yet; the header gate and all 50 tests were run locally. The first push may need small tweaks (for example, ZAP's `-I` flag keeps warnings from failing the build; remove it to be stricter).
- `gitleaks-action` is free for personal repos; organisation repos need a license key.
- HSTS only takes effect over HTTPS. Behind a real deployment, terminate TLS first, then add `preload` to the HSTS preload list only when you are sure every subdomain supports HTTPS.
