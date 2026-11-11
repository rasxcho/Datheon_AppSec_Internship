import { createDeps, type Deps } from "../src/lib/deps.js";
import { createRouter } from "../src/router.js";

export const SECRET = "unit-test-secret-".padEnd(48, "x");

export function makeApi(overrides: Partial<Deps> = {}) {
  const clock = { now: 1_800_000_000_000 }; // fixed, movable clock => deterministic expiry and rate-limit tests
  const deps = createDeps({ secret: SECRET, secureCookies: false, enableVulnerableLab: true, now: () => clock.now, ...overrides });
  return { deps, clock, api: createRouter(deps) };
}

export type Api = ReturnType<typeof makeApi>["api"];

interface CallOptions { cookie?: string; ip?: string; body?: unknown }

export function call(api: Api, method: string, path: string, options: CallOptions = {}): Promise<Response> {
  const headers: Record<string, string> = { "x-client-ip": options.ip ?? "10.0.0.1" };
  if (options.cookie) headers.cookie = options.cookie;
  if (options.body !== undefined) headers["content-type"] = "application/json";
  return api(new Request(`http://lab.test${path}`, {
    method,
    headers,
    body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
  }));
}

/** Logs in and returns the cookie pair ("name=value") a browser would send back. */
export async function login(api: Api, email: string, password: string, ip = "10.0.0.1") {
  const res = await call(api, "POST", "/api/auth/login", { body: { email, password }, ip });
  const setCookie = res.headers.getSetCookie()[0] ?? "";
  return { res, setCookie, cookie: setCookie.split(";")[0] ?? "" };
}

export const ALICE = { email: "alice@example.com", password: "Alice#Lab-2026" };
export const BOB = { email: "bob@example.com", password: "Bob#Lab-2026!" };
