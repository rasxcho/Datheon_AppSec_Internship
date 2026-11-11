/** BASELINE (before Task 2): blind single-parameter lookup, no authentication, no ownership check. */
import type { Deps } from "../lib/deps.js";
import { json } from "../lib/http.js";

export function dashboardHandler(deps: Deps) {
  return async function GET(request: Request): Promise<Response> {
    const appId = new URL(request.url).searchParams.get("appId") ?? "";
    const record = deps.db.findByAppId(appId);
    if (!record) return json(404, { error: `No application found for appId=${appId}` });
    return json(200, record);
  };
}
