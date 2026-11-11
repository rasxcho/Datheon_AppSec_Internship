import { ACCESS_TOKEN_TTL_SECONDS } from "./config.js";
import type { Deps } from "./deps.js";
import { verifyToken, type Claims } from "./jwt.js";

/** "__Host-" prefix: browser only accepts the cookie if Secure, Path=/ and no Domain are set. */
export const cookieName = (secure: boolean): string => (secure ? "__Host-dt_session" : "dt_session");

export function parseCookies(header: string | null): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of (header ?? "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}

export function sessionCookie(token: string, secure: boolean): string {
  const attrs = [`${cookieName(secure)}=${token}`, "Path=/", "HttpOnly", "SameSite=Lax", `Max-Age=${ACCESS_TOKEN_TTL_SECONDS}`];
  if (secure) attrs.push("Secure");
  return attrs.join("; ");
}

export function clearedCookie(secure: boolean): string {
  const attrs = [`${cookieName(secure)}=`, "Path=/", "HttpOnly", "SameSite=Lax", "Max-Age=0", "Expires=Thu, 01 Jan 1970 00:00:00 GMT"];
  if (secure) attrs.push("Secure");
  return attrs.join("; ");
}

/** Identity comes only from a valid, unexpired, unrevoked signed cookie. Never from query params or body. */
export function authenticate(request: Request, deps: Deps): Claims | null {
  const token = parseCookies(request.headers.get("cookie"))[cookieName(deps.secureCookies)];
  if (!token) return null;
  const claims = verifyToken(token, deps.secret, deps.now());
  if (!claims || deps.tokens.isRevoked(claims.jti)) return null;
  return claims;
}
