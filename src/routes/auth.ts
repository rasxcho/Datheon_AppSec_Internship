/** Session endpoints (Task 3): login, refresh (rotation), logout, me. */
import { ACCESS_TOKEN_TTL_SECONDS } from "../lib/config.js";
import { DUMMY_HASH, verifyPassword } from "../lib/password.js";
import { clientIp, json, readJson } from "../lib/http.js";
import type { Deps } from "../lib/deps.js";
import { signToken } from "../lib/jwt.js";
import { rateLimitHeaders } from "../lib/rateLimit.js";
import { authenticate, clearedCookie, sessionCookie } from "../lib/session.js";

export function authHandlers(deps: Deps) {
  const issue = (email: string, role: string): string =>
    sessionCookie(signToken({ sub: email, email, role }, deps.secret, ACCESS_TOKEN_TTL_SECONDS, deps.now()), deps.secureCookies);

  return {
    async login(request: Request): Promise<Response> {
      const limit = deps.loginLimiter.check(`login:${clientIp(request)}`);
      const headers = rateLimitHeaders(limit);
      if (!limit.allowed) return json(429, { error: "Too many attempts, try again later" }, { headers });

      const body = await readJson(request);
      const email = typeof body?.email === "string" ? body.email.trim().toLowerCase().slice(0, 254) : "";
      const password = typeof body?.password === "string" ? body.password.slice(0, 200) : "";

      const user = deps.db.findUser(email);
      const valid = verifyPassword(password, user?.passwordHash ?? DUMMY_HASH); // always hash: no timing oracle
      if (!user || !valid) return json(401, { error: "Invalid email or password" }, { headers }); // one message for both cases

      // The token travels only in the HttpOnly cookie. It is deliberately NOT in the JSON body,
      // so front-end JavaScript (and therefore XSS) never sees it.
      return json(200, { user: { email: user.email, role: user.role }, expiresInSeconds: ACCESS_TOKEN_TTL_SECONDS }, {
        headers,
        cookies: [issue(user.email, user.role)],
      });
    },

    /** Rotation: the presented token is revoked and replaced, so a stolen copy stops working after the next refresh. */
    async refresh(request: Request): Promise<Response> {
      const claims = authenticate(request, deps);
      if (!claims) return json(401, { error: "Authentication required" });
      deps.tokens.revoke(claims.jti, claims.exp, deps.now());
      return json(200, { expiresInSeconds: ACCESS_TOKEN_TTL_SECONDS }, { cookies: [issue(claims.email, claims.role)] });
    },

    async logout(request: Request): Promise<Response> {
      const claims = authenticate(request, deps);
      if (claims) deps.tokens.revoke(claims.jti, claims.exp, deps.now()); // server-side kill, not just cookie removal
      return json(200, { ok: true }, { cookies: [clearedCookie(deps.secureCookies)] });
    },

    async me(request: Request): Promise<Response> {
      const claims = authenticate(request, deps);
      if (!claims) return json(401, { error: "Authentication required" });
      return json(200, { email: claims.email, role: claims.role, expiresAt: new Date(claims.exp * 1000).toISOString() });
    },
  };
}
