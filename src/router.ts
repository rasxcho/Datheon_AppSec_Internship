import type { Deps } from "./lib/deps.js";
import { json } from "./lib/http.js";
import { vulnerableDashboardHandler } from "./lab/vulnerableDashboard.js";
import { authHandlers } from "./routes/auth.js";
import { dashboardHandler } from "./routes/dashboard.js";
import { dashboardPage } from "./routes/page.js";
import { publicVerifyHandler } from "./routes/publicVerify.js";
import { applySecurityHeaders } from "./lib/securityHeaders.js";

type Handler = (request: Request) => Promise<Response>;

/**
 * Framework-neutral router. Every handler is `(Request) => Promise<Response>`, exactly the shape of a
 * Next.js App Router route handler, so each one can be re-exported as `export const GET = ...` in app/api/**.
 */
export function createRouter(deps: Deps): (request: Request) => Promise<Response> {
  const auth = authHandlers(deps);
  const routes: Record<string, Record<string, Handler>> = {
    "/api/health": { GET: async () => json(200, { status: "ok" }) },
    "/api/auth/login": { POST: auth.login },
    "/api/auth/refresh": { POST: auth.refresh },
    "/api/auth/logout": { POST: auth.logout },
    "/api/auth/me": { GET: auth.me },
    "/api/dashboard": { GET: dashboardHandler(deps) },
    "/api/public/verify": { GET: publicVerifyHandler(deps) },
    "/dashboard": { GET: dashboardPage("/api/dashboard", "My application (secured)") },
  };
  if (deps.enableVulnerableLab) {
    routes["/api/vulnerable/dashboard"] = { GET: vulnerableDashboardHandler(deps) };
    routes["/lab/dashboard"] = { GET: dashboardPage("/api/vulnerable/dashboard", "Applicant dashboard (Task 1 lab target)") };
  }

  return async function route(request: Request): Promise<Response> {
    return applySecurityHeaders(await dispatch(request));
  };

  async function dispatch(request: Request): Promise<Response> {
    try {
      const { pathname } = new URL(request.url);
      const methods = routes[pathname];
      if (!methods) return json(404, { error: "Not found" });
      const handler = methods[request.method.toUpperCase()];
      if (!handler) return json(405, { error: "Method not allowed" }, { headers: { Allow: Object.keys(methods).join(", ") } });
      return await handler(request);
    } catch {
      return json(500, { error: "Internal server error" }); // log server-side; never return stack traces or DB details
    }
  }
}
