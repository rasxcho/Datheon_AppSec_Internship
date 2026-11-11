import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { call, makeApi } from "./helpers.js";

describe("Task 1 lab - intentionally vulnerable route (documents the finding)", () => {
  it("returns another user's PII with no cookie or header at all", async () => {
    const { api } = makeApi();
    const res = await call(api, "GET", "/api/vulnerable/dashboard?appId=DT-2026-002");
    assert.equal(res.status, 200);
    const body = (await res.json()) as Record<string, string>;
    assert.equal(body.name, "Bob Raman");
    assert.ok(body.phone && body.notes && body.ownerEmail);
  });

  it("allows sequential enumeration of every application", async () => {
    const { api } = makeApi();
    let found = 0;
    for (let i = 1; i <= 5; i++) {
      if ((await call(api, "GET", `/api/vulnerable/dashboard?appId=DT-2026-00${i}`)).status === 200) found++;
    }
    assert.equal(found, 5);
  });

  it("is not mounted when the lab flag is off (as in production)", async () => {
    const { api } = makeApi({ enableVulnerableLab: false });
    assert.equal((await call(api, "GET", "/api/vulnerable/dashboard?appId=DT-2026-001")).status, 404);
  });
});

describe("Task 1 lab - dashboard page (client-side routing)", () => {
  it("serves a page that holds no personal data and fetches it from the API by URL parameter", async () => {
    const { api } = makeApi();
    const res = await call(api, "GET", "/lab/dashboard?appId=DT-2026-002");
    assert.equal(res.status, 200);
    assert.match(res.headers.get("content-type") ?? "", /text\/html/);
    const page = await res.text();
    assert.ok(page.includes("/api/vulnerable/dashboard"));
    assert.ok(!page.includes("Bob Raman") && !page.includes("90000"), "page must not embed records");
  });

  it("ships a nonce-based CSP and renders values with textContent (no innerHTML)", async () => {
    const { api } = makeApi();
    const res = await call(api, "GET", "/lab/dashboard");
    const csp = res.headers.get("content-security-policy") ?? "";
    assert.match(csp, /script-src 'nonce-/);
    assert.match(csp, /frame-ancestors 'none'/);
    assert.ok(!(await res.text()).includes("innerHTML"));
  });

  it("secured page targets the hardened API; lab page is absent when the lab is off", async () => {
    const { api } = makeApi({ enableVulnerableLab: false });
    assert.ok((await (await call(api, "GET", "/dashboard")).text()).includes('"/api/dashboard"'));
    assert.equal((await call(api, "GET", "/lab/dashboard")).status, 404);
  });
});
