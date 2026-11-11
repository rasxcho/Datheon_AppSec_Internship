import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { getSecret } from "../src/lib/config.js";
import { signToken, verifyToken } from "../src/lib/jwt.js";
import { SlidingWindowLimiter } from "../src/lib/rateLimit.js";
import { ALICE, BOB, SECRET, call, login, makeApi } from "./helpers.js";

describe("Task 3 - cookie sessions", () => {
  it("sets an HttpOnly, SameSite=Lax, expiring cookie and keeps the token out of the JSON body", async () => {
    const { api } = makeApi();
    const { res, setCookie, cookie } = await login(api, ALICE.email, ALICE.password);
    assert.equal(res.status, 200);
    assert.match(setCookie, /HttpOnly/);
    assert.match(setCookie, /SameSite=Lax/);
    assert.match(setCookie, /Max-Age=900/);
    assert.match(setCookie, /Path=\//);
    const token = cookie.split("=")[1]!;
    assert.ok(!JSON.stringify(await res.json()).includes(token), "token must not be readable by page JavaScript");
  });

  it("production mode adds Secure and the __Host- prefix, and still authenticates", async () => {
    const { api } = makeApi({ secureCookies: true });
    const { setCookie, cookie } = await login(api, ALICE.email, ALICE.password);
    assert.match(setCookie, /^__Host-dt_session=/);
    assert.match(setCookie, /; Secure/);
    assert.equal((await call(api, "GET", "/api/auth/me", { cookie })).status, 200);
  });

  it("gives identical answers for a wrong password and an unknown account", async () => {
    const { api } = makeApi();
    const wrong = await login(api, ALICE.email, "nope", "10.0.0.2");
    const unknown = await login(api, "ghost@example.com", "nope", "10.0.0.3");
    assert.equal(wrong.res.status, 401);
    assert.equal(unknown.res.status, 401);
    assert.deepEqual(await wrong.res.json(), await unknown.res.json());
    assert.equal(wrong.setCookie, "");
  });

  it("expires tokens after 15 minutes", async () => {
    const { api, clock } = makeApi();
    const { cookie } = await login(api, ALICE.email, ALICE.password);
    assert.equal((await call(api, "GET", "/api/auth/me", { cookie })).status, 200);
    clock.now += 14 * 60 * 1000;
    assert.equal((await call(api, "GET", "/api/auth/me", { cookie })).status, 200);
    clock.now += 2 * 60 * 1000;
    assert.equal((await call(api, "GET", "/api/auth/me", { cookie })).status, 401);
  });

  it("rotates on refresh: the old token dies, the new one works", async () => {
    const { api } = makeApi();
    const first = await login(api, ALICE.email, ALICE.password);
    const refreshed = await call(api, "POST", "/api/auth/refresh", { cookie: first.cookie });
    assert.equal(refreshed.status, 200);
    const next = (refreshed.headers.getSetCookie()[0] ?? "").split(";")[0]!;
    assert.notEqual(next, first.cookie);
    assert.equal((await call(api, "GET", "/api/auth/me", { cookie: first.cookie })).status, 401); // replay of old token
    assert.equal((await call(api, "GET", "/api/auth/me", { cookie: next })).status, 200);
  });

  it("logout revokes server-side, so a copied cookie cannot be replayed", async () => {
    const { api } = makeApi();
    const { cookie } = await login(api, BOB.email, BOB.password);
    const out = await call(api, "POST", "/api/auth/logout", { cookie });
    assert.match(out.headers.getSetCookie()[0] ?? "", /Max-Age=0/);
    assert.equal((await call(api, "GET", "/api/auth/me", { cookie })).status, 401);
  });
});

describe("Task 3 - login rate limiting", () => {
  it("exposes X-RateLimit headers and counts down", async () => {
    const { api } = makeApi();
    const remaining: string[] = [];
    for (let i = 0; i < 3; i++) {
      const { res } = await login(api, ALICE.email, "wrong", "198.51.100.7");
      assert.equal(res.headers.get("x-ratelimit-limit"), "5");
      remaining.push(res.headers.get("x-ratelimit-remaining")!);
    }
    assert.deepEqual(remaining, ["4", "3", "2"]);
  });

  it("blocks brute force: attempt 6 gets 429 + Retry-After, even with the right password", async () => {
    const { api } = makeApi();
    for (let i = 0; i < 5; i++) assert.equal((await login(api, ALICE.email, `guess${i}`, "198.51.100.7")).res.status, 401);
    const blocked = await login(api, ALICE.email, ALICE.password, "198.51.100.7");
    assert.equal(blocked.res.status, 429);
    assert.ok(Number(blocked.res.headers.get("retry-after")) >= 1);
    assert.equal(blocked.setCookie, "");
  });

  it("recovers after the window and does not affect other clients", async () => {
    const { api, clock } = makeApi();
    for (let i = 0; i < 5; i++) await login(api, ALICE.email, "x", "198.51.100.7");
    assert.equal((await login(api, BOB.email, BOB.password, "198.51.100.8")).res.status, 200); // different IP
    clock.now += 61_000;
    assert.equal((await login(api, ALICE.email, ALICE.password, "198.51.100.7")).res.status, 200);
  });
});

describe("Task 3 - sliding window limiter", () => {
  it("does not allow a double burst across a fixed-window boundary", () => {
    let t = 0;
    const limiter = new SlidingWindowLimiter(3, 10_000, () => t);
    const at = (ms: number) => { t = ms; return limiter.check("k").allowed; };
    assert.deepEqual([at(8_000), at(9_000), at(9_500)], [true, true, true]);
    assert.equal(at(10_500), false); // a fixed 10s bucket would have reset here; the sliding window has not
    assert.equal(at(18_100), true);  // first hit (t=8s) has now left the window
  });

  it("reports retry time and per-key isolation", () => {
    let t = 0;
    const limiter = new SlidingWindowLimiter(1, 10_000, () => t);
    assert.equal(limiter.check("a").allowed, true);
    t = 4_000;
    const denied = limiter.check("a");
    assert.equal(denied.allowed, false);
    assert.equal(denied.retryAfterSeconds, 6);
    assert.equal(limiter.check("b").allowed, true);
  });
});

describe("Task 3 - JWT verification", () => {
  const now = 1_800_000_000_000;
  const payload = { sub: "a@x.io", email: "a@x.io", role: "student" };

  it("round-trips valid tokens and gives each token a unique id", () => {
    const a = signToken(payload, SECRET, 60, now);
    const b = signToken(payload, SECRET, 60, now);
    assert.equal(verifyToken(a, SECRET, now)?.email, "a@x.io");
    assert.notEqual(verifyToken(a, SECRET, now)?.jti, verifyToken(b, SECRET, now)?.jti);
  });

  it("rejects wrong secret, tampering, garbage, and expiry at the boundary", () => {
    const t = signToken(payload, SECRET, 60, now);
    assert.equal(verifyToken(t, "other".padEnd(40, "z"), now), null);
    assert.equal(verifyToken(t.slice(0, -2) + "xx", SECRET, now), null);
    assert.equal(verifyToken("not.a.jwt", SECRET, now), null);
    assert.equal(verifyToken("", SECRET, now), null);
    assert.notEqual(verifyToken(t, SECRET, now + 59_000), null);
    assert.equal(verifyToken(t, SECRET, now + 60_000), null);
  });
});

describe("Task 3 - secret management", () => {
  it("production refuses to start without a strong JWT_SECRET", () => {
    const saved = { env: process.env.NODE_ENV, secret: process.env.JWT_SECRET };
    try {
      process.env.NODE_ENV = "production";
      delete process.env.JWT_SECRET;
      assert.throws(() => getSecret(), /JWT_SECRET/);
      process.env.JWT_SECRET = "short";
      assert.throws(() => getSecret(), /JWT_SECRET/);
      process.env.JWT_SECRET = "s".repeat(32);
      assert.equal(getSecret(), "s".repeat(32));
    } finally {
      if (saved.env === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = saved.env;
      if (saved.secret === undefined) delete process.env.JWT_SECRET; else process.env.JWT_SECRET = saved.secret;
    }
  });
});
