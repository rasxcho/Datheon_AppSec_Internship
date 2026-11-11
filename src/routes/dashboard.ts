/**
 * GET /api/dashboard?appId=DT-2026-001   (hardened - Task 2)
 *
 * Authorization order matters:
 *   1. throttle           -> slows ID guessing, even by unauthenticated callers
 *   2. authenticate       -> identity from the signed session cookie only (401)
 *   3. validate the id    -> strict format, so odd input never reaches the data layer
 *   4. query by id AND owner -> a record that is not yours is indistinguishable from one that does not exist (404)
 */
import { clientIp, json } from "../lib/http.js";
import type { Deps } from "../lib/deps.js";
import { rateLimitHeaders } from "../lib/rateLimit.js";
import { authenticate } from "../lib/session.js";

const APP_ID_PATTERN = /^DT-\d{4}-\d{3}$/;

export function dashboardHandler(deps: Deps) {
  return async function GET(request: Request): Promise<Response> {
    const limit = deps.lookupLimiter.check(`lookup:${clientIp(request)}`);
    const headers = rateLimitHeaders(limit);
    if (!limit.allowed) return json(429, { error: "Too many requests" }, { headers });

    const session = authenticate(request, deps);
    if (!session) return json(401, { error: "Authentication required" }, { headers });

    const appId = new URL(request.url).searchParams.get("appId") ?? "";
    const record = APP_ID_PATTERN.test(appId) ? deps.db.findByAppIdForOwner(appId, session.email) : undefined;
    if (!record) return json(404, { error: "Not found" }, { headers }); // same body for missing and not-yours

    // Return only what the dashboard needs: no ownerEmail, no internal fields.
    const { name, email, phone, notes } = record;
    return json(200, { appId: record.appId, name, email, phone, notes }, { headers });
  };
}
