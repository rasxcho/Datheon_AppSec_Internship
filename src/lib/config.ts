import { randomBytes } from "node:crypto";

export const ACCESS_TOKEN_TTL_SECONDS = 15 * 60; // short-lived: limits the window if a token leaks

export const isProduction = (): boolean => process.env.NODE_ENV === "production";

const devSecret = randomBytes(32).toString("hex"); // new on every start, never committed

/** HMAC signing key. Production refuses to start without a strong key from the environment. */
export function getSecret(): string {
  const fromEnv = process.env.JWT_SECRET;
  if (fromEnv && fromEnv.length >= 32) return fromEnv;
  if (isProduction()) throw new Error("JWT_SECRET (at least 32 characters) is required in production");
  return devSecret;
}
