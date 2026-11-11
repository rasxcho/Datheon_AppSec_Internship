/**
 * INTENTIONALLY VULNERABLE (Task 1 target) - GET /api/vulnerable/dashboard?appId=DT-2026-001
 * Mounted only when ENABLE_VULNERABLE_LAB is on and NODE_ENV is not "production".
 *
 * Flaws: no authentication, no ownership check, sequential guessable ids,
 * returns the whole record, and the error message echoes the input.
 */
import type { Deps } from "../lib/deps.js";
import { json } from "../lib/http.js";

export function vulnerableDashboardHandler(deps: Deps) {
  return async function GET(request: Request): Promise<Response> {
    const appId = new URL(request.url).searchParams.get("appId") ?? "";
    const record = deps.db.findByAppId(appId); // blind single-parameter lookup
    if (!record) return json(404, { error: `No application found for appId=${appId}` });
    return json(200, record);
  };
}
