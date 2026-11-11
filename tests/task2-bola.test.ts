import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { signToken } from "../src/lib/jwt.js";
import { ALICE, BOB, call, login, makeApi } from "./helpers.js";

const b64 = (v: unknown) => Buffer.from(JSON.stringify(v)).toString("base64url");

describe("Task 2 - hardened /api/dashboard (BOLA / IDOR)", () => {
  it("rejects requests with no session (401) and returns no personal data", async () => {
    const { api } = makeApi();
    const res = await call(api, "GET", "/api/dashboard?appId=DT-2026-001");
    assert.equal(res.status, 401);
    assert.deepEqual(await res.json(), { error: "Authentication required" });
  });

  it("lets a user read their own record, with only the intended fields", async () => {
    const { api } = makeApi();
    const { cookie } = await login(api, ALICE.email, ALICE.password);
    const res = await call(api, "GET", "/api/dashboard?appId=DT-2026-001", { cookie });
    assert.equal(res.status, 200);
    const body = (await res.json()) as Record<string, string>;
    assert.equal(body.email, "alice@example.com");
    assert.deepEqual(Object.keys(body).sort(), ["appId", "email", "name", "notes", "phone"]);
  });

  it("User A cannot read User B's record, and the answer matches a record that does not exist", async () => {
    const { api } = makeApi();
    const { cookie } = await login(api, ALICE.email, ALICE.password);
    const foreign = await call(api, "GET", "/api/dashboard?appId=DT-2026-002", { cookie }); // Bob's
    const missing = await call(api, "GET", "/api/dashboard?appId=DT-2026-999", { cookie });
    assert.equal(foreign.status, 404);
    assert.equal(missing.status, 404);
    assert.deepEqual(await foreign.json(), await missing.json()); // no oracle for "this id exists"
  });

  it("works in both directions (Bob cannot read Alice's record)", async () => {
    const { api } = makeApi();
    const { cookie } = await login(api, BOB.email, BOB.password);
    assert.equal((await call(api, "GET", "/api/dashboard?appId=DT-2026-001", { cookie })).status, 404);
    assert.equal((await call(api, "GET", "/api/dashboard?appId=DT-2026-002", { cookie })).status, 200);
  });

  it("rejects malformed or hostile identifiers without touching the data layer", async () => {
    const { api } = makeApi();
    const { cookie } = await login(api, ALICE.email, ALICE.password);
    for (const bad of ["' OR 1=1 --", "../../etc/passwd", "DT-2026-001%00", "DT-2026-001 ", "", "*"]) {
      const res = await call(api, "GET", `/api/dashboard?appId=${encodeURIComponent(bad)}`, { cookie });
      assert.equal(res.status, 404, `appId=${JSON.stringify(bad)}`);
      assert.deepEqual(await res.json(), { error: "Not found" });
    }
  });

  it("cannot be bypassed by sending the id in a header or another user's email", async () => {
    const { api } = makeApi();
    const res = await api(new Request("http://lab.test/api/dashboard?appId=DT-2026-002", {
      headers: { "x-user-email": "bob@example.com", "x-client-ip": "10.0.0.1" },
    }));
    assert.equal(res.status, 401);
  });

  describe("forged and stale tokens are refused", () => {
    it("alg:none token", async () => {
      const { api } = makeApi();
      const exp = Math.floor(Date.now() / 1000) + 3600;
      const token = `${b64({ alg: "none", typ: "JWT" })}.${b64({ sub: "bob@example.com", email: "bob@example.com", role: "student", jti: "x", iat: 1, exp })}.`;
      const res = await call(api, "GET", "/api/dashboard?appId=DT-2026-002", { cookie: `dt_session=${token}` });
      assert.equal(res.status, 401);
    });

    it("payload edited after signing (alice -> bob)", async () => {
      const { api } = makeApi();
      const { cookie } = await login(api, ALICE.email, ALICE.password);
      const [h, p, s] = cookie.split("=")[1]!.split(".") as [string, string, string];
      const claims = JSON.parse(Buffer.from(p, "base64url").toString()) as Record<string, unknown>;
      claims.email = "bob@example.com";
      const forged = `${h}.${b64(claims)}.${s}`;
      const res = await call(api, "GET", "/api/dashboard?appId=DT-2026-002", { cookie: `dt_session=${forged}` });
      assert.equal(res.status, 401);
    });

    it("token signed with a different secret", async () => {
      const { api, clock } = makeApi();
      const token = signToken({ sub: "bob@example.com", email: "bob@example.com", role: "student" }, "attacker-secret".padEnd(40, "!"), 900, clock.now);
      assert.equal((await call(api, "GET", "/api/dashboard?appId=DT-2026-002", { cookie: `dt_session=${token}` })).status, 401);
    });

    it("expired token", async () => {
      const { api, clock } = makeApi();
      const { cookie } = await login(api, ALICE.email, ALICE.password);
      clock.now += 16 * 60 * 1000;
      assert.equal((await call(api, "GET", "/api/dashboard?appId=DT-2026-001", { cookie })).status, 401);
    });
  });

  it("never leaks stack traces or internals when something breaks", async () => {
    const { api } = makeApi();
    const { cookie } = await login(api, ALICE.email, ALICE.password);
    const { api: brokenApi } = makeApi({
      db: { findUser: () => undefined, findByAppIdForOwner: () => { throw new Error("connection to db-prod-01:5432 refused"); } } as never,
    });
    // Same secret and clock, so the cookie is valid for the second app instance.
    const res = await call(brokenApi, "GET", "/api/dashboard?appId=DT-2026-001", { cookie });
    assert.equal(res.status, 500);
    const text = await res.text();
    assert.deepEqual(JSON.parse(text), { error: "Internal server error" });
    assert.ok(!/db-prod|5432|Error:|\bat \w+/.test(text));
  });

  it("throttles ID enumeration, including by unauthenticated callers", async () => {
    const { api } = makeApi();
    const statuses: number[] = [];
    for (let i = 1; i <= 40; i++) statuses.push((await call(api, "GET", `/api/dashboard?appId=DT-2026-${String(i).padStart(3, "0")}`, { ip: "203.0.113.9" })).status);
    assert.equal(statuses.filter((s) => s === 401).length, 30);
    assert.equal(statuses.filter((s) => s === 429).length, 10);
    const limited = await call(api, "GET", "/api/dashboard?appId=DT-2026-001", { ip: "203.0.113.9" });
    assert.ok(Number(limited.headers.get("retry-after")) >= 1);
  });

  it("sets no-store and nosniff on responses", async () => {
    const { api } = makeApi();
    const res = await call(api, "GET", "/api/dashboard?appId=DT-2026-001");
    assert.equal(res.headers.get("cache-control"), "no-store");
    assert.equal(res.headers.get("x-content-type-options"), "nosniff");
  });
});
