import { getSecret, isProduction } from "./config.js";
import { Database, seedDatabase } from "./db.js";
import { SlidingWindowLimiter } from "./rateLimit.js";
import { TokenStore } from "./tokenStore.js";

export interface Deps {
  secret: string;
  secureCookies: boolean;
  enableVulnerableLab: boolean;
  now: () => number;
  db: Database;
  tokens: TokenStore;
  loginLimiter: SlidingWindowLimiter;
  lookupLimiter: SlidingWindowLimiter;
}

export function createDeps(overrides: Partial<Deps> = {}): Deps {
  const now = overrides.now ?? Date.now;
  return {
    secret: getSecret(),
    secureCookies: isProduction(),
    enableVulnerableLab: !isProduction(), // the intentionally flawed route can never be mounted in production
    now,
    db: seedDatabase(),
    tokens: new TokenStore(),
    loginLimiter: new SlidingWindowLimiter(5, 60_000, now),   // 5 login attempts / minute / IP
    lookupLimiter: new SlidingWindowLimiter(30, 60_000, now), // 30 record lookups / minute / IP
    ...overrides,
  };
}
