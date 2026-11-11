export interface RateLimitResult {
  allowed: boolean;
  limit: number;
  remaining: number;
  resetSeconds: number; // until the oldest counted request leaves the window
  retryAfterSeconds: number; // only meaningful when denied
}

/**
 * Sliding-window limiter: counts requests in the last `windowMs` (not a fixed bucket),
 * so a burst straddling a minute boundary cannot double the allowance.
 * In-memory; swap the Map for Redis (ZADD/ZREMRANGEBYSCORE/ZCARD) to share state across instances.
 */
export class SlidingWindowLimiter {
  private readonly hits = new Map<string, number[]>();

  constructor(
    private readonly limit: number,
    private readonly windowMs: number,
    private readonly now: () => number = Date.now,
  ) {}

  check(key: string): RateLimitResult {
    const t = this.now();
    const fresh = (this.hits.get(key) ?? []).filter((ts) => ts > t - this.windowMs);

    if (fresh.length >= this.limit) {
      this.hits.set(key, fresh);
      const wait = Math.max(1, Math.ceil((fresh[0]! + this.windowMs - t) / 1000));
      return { allowed: false, limit: this.limit, remaining: 0, resetSeconds: wait, retryAfterSeconds: wait };
    }

    fresh.push(t);
    this.hits.set(key, fresh);
    if (this.hits.size > 10_000) this.sweep(t);
    const reset = Math.max(1, Math.ceil((fresh[0]! + this.windowMs - t) / 1000));
    return { allowed: true, limit: this.limit, remaining: this.limit - fresh.length, resetSeconds: reset, retryAfterSeconds: 0 };
  }

  private sweep(t: number): void {
    for (const [key, stamps] of this.hits) {
      if (stamps.every((ts) => ts <= t - this.windowMs)) this.hits.delete(key);
    }
  }
}

export function rateLimitHeaders(r: RateLimitResult): Record<string, string> {
  const h: Record<string, string> = {
    "X-RateLimit-Limit": String(r.limit),
    "X-RateLimit-Remaining": String(r.remaining),
    "X-RateLimit-Reset": String(r.resetSeconds),
  };
  if (!r.allowed) h["Retry-After"] = String(r.retryAfterSeconds);
  return h;
}
