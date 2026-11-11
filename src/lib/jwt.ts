import { createHmac, randomUUID, timingSafeEqual } from "node:crypto";

export interface Claims {
  sub: string;
  email: string;
  role: string;
  jti: string; // unique id, lets us revoke / rotate a single token
  iat: number; // seconds
  exp: number; // seconds
}

const b64url = (input: string | Buffer): string => Buffer.from(input).toString("base64url");
const sign = (data: string, secret: string): Buffer => createHmac("sha256", secret).update(data).digest();

/** Create an HS256 JWT. */
export function signToken(
  payload: { sub: string; email: string; role: string },
  secret: string,
  ttlSeconds: number,
  nowMs: number = Date.now(),
): string {
  const iat = Math.floor(nowMs / 1000);
  const claims: Claims = { ...payload, jti: randomUUID(), iat, exp: iat + ttlSeconds };
  const head = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = b64url(JSON.stringify(claims));
  const sig = b64url(sign(`${head}.${body}`, secret));
  return `${head}.${body}.${sig}`;
}

/**
 * Verify signature, algorithm and expiry. Returns the claims or null; never throws.
 * The algorithm is pinned to HS256, so "alg":"none" and algorithm-confusion tokens are rejected.
 */
export function verifyToken(token: string, secret: string, nowMs: number = Date.now()): Claims | null {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const [head, body, sig] = parts as [string, string, string];

    const header = JSON.parse(Buffer.from(head, "base64url").toString("utf8")) as { alg?: unknown; typ?: unknown };
    if (header.alg !== "HS256" || header.typ !== "JWT") return null;

    const expected = sign(`${head}.${body}`, secret);
    const given = Buffer.from(sig, "base64url");
    if (given.length !== expected.length || !timingSafeEqual(given, expected)) return null;

    const c = JSON.parse(Buffer.from(body, "base64url").toString("utf8")) as Partial<Claims>;
    if (
      typeof c.sub !== "string" || typeof c.email !== "string" || typeof c.role !== "string" ||
      typeof c.jti !== "string" || typeof c.iat !== "number" || typeof c.exp !== "number"
    ) return null;
    if (c.exp * 1000 <= nowMs) return null; // expired
    if (c.iat * 1000 > nowMs + 60_000) return null; // issued in the future (clock tamper)
    return c as Claims;
  } catch {
    return null;
  }
}
