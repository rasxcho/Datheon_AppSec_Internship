import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { maskEmail, maskName, maskPhone } from "../src/lib/mask.js";
import { SECURITY_HEADERS } from "../src/lib/securityHeaders.js";
import { call, makeApi } from "./helpers.js";

describe("Task 4 - masking utility", () => {
  it("masks email addresses, keeping first/last character and the domain", () => {
    assert.equal(maskEmail("alice@example.com"), "a***e@example.com");
    assert.equal(maskEmail("john@domain.com"), "j***n@domain.com");
    assert.equal(maskEmail("ab@x.org"), "a***@x.org");
  });
  it("fails closed on malformed email input", () => {
    for (const bad of ["", "no-at-sign", "@domain.com", "user@"]) assert.equal(maskEmail(bad), "***");
  });
  it("masks phone numbers except the last two digits, keeping separators", () => {
    assert.equal(maskPhone("+91 90000 00001"), "+** ***** ***01");
    assert.equal(maskPhone("1234"), "****");
    assert.equal(maskPhone("none"), "***");
  });
  it("masks names to initials with fixed-width stars", () => {
    assert.equal(maskName("Alice Kumar"), "A*** K***");
    assert.equal(maskName("  "), "***");
  });
});

describe("Task 4 - public verification endpoint", () => {
  it("works with NO login and returns only masked PII", async () => {
    const { api } = makeApi();
    const res = await call(api, "GET", "/api/public/verify?certId=DT-CERT-7F3K9Q2M");
    assert.equal(res.status, 200);
    const body = (await res.json()) as Record<string, unknown>;
    assert.equal(body.valid, true);
    assert.equal(body.holder, "A*** K***");
    assert.equal(body.email, "a***e@example.com");
    assert.equal(body.phone, "+** ***** ***01");
  });

  it("never leaks raw PII or internal fields anywhere in the payload", async () => {
    const { api } = makeApi();
    const text = await (await call(api, "GET", "/api/public/verify?certId=DT-CERT-7F3K9Q2M")).text();
    for (const secret of ["alice@example.com", "Alice", "Kumar", "90000 00001", "DT-2026-001", "ownerEmail", "Shortlisted"]) {
      assert.ok(!text.includes(secret), `payload leaked ${secret}`);
    }
  });

  it("returns an allow-listed set of fields only", async () => {
    const { api } = makeApi();
    const body = (await (await call(api, "GET", "/api/public/verify?certId=DT-CERT-4B8N1X6D")).json()) as Record<string, unknown>;
    assert.deepEqual(Object.keys(body).sort(), ["certificateId", "email", "holder", "issuedOn", "phone", "program", "status", "valid"]);
  });

  it("returns no holder details for a revoked certificate", async () => {
    const { api } = makeApi();
    const body = await (await call(api, "GET", "/api/public/verify?certId=DT-CERT-9H2T5W0R")).json();
    assert.deepEqual(body, { valid: false, certificateId: "DT-CERT-9H2T5W0R", status: "revoked" });
  });

  it("gives identical 404s for unknown and malformed ids (no existence oracle)", async () => {
    const { api } = makeApi();
    const unknown = await call(api, "GET", "/api/public/verify?certId=DT-CERT-AAAAAAAA");
    const malformed = await call(api, "GET", "/api/public/verify?certId=' OR 1=1--");
    const missing = await call(api, "GET", "/api/public/verify");
    for (const r of [unknown, malformed, missing]) assert.equal(r.status, 404);
    assert.deepEqual(await unknown.json(), await malformed.json());
  });

  it("cannot be used to enumerate internal application ids", async () => {
    const { api } = makeApi();
    assert.equal((await call(api, "GET", "/api/public/verify?certId=DT-2026-001")).status, 404);
  });

  it("throttles bulk scraping per IP (429 after 30 lookups/minute)", async () => {
    const { api } = makeApi();
    let last = 0;
    for (let i = 0; i < 31; i++) last = (await call(api, "GET", "/api/public/verify?certId=DT-CERT-AAAAAAAA", { ip: "10.9.9.9" })).status;
    assert.equal(last, 429);
  });
});

describe("Task 4 - security headers", () => {
  const paths: Array<[string, string]> = [
    ["GET", "/api/health"],
    ["GET", "/api/public/verify?certId=DT-CERT-7F3K9Q2M"],
    ["GET", "/api/dashboard"], // 401
    ["GET", "/no-such-route"], // 404
    ["DELETE", "/api/health"], // 405
  ];
  for (const [method, path] of paths) {
    it(`sets every baseline header on ${method} ${path}`, async () => {
      const { api } = makeApi();
      const res = await call(api, method, path);
      for (const name of Object.keys(SECURITY_HEADERS)) assert.ok(res.headers.get(name), `${name} missing (HTTP ${res.status})`);
      assert.equal(res.headers.get("x-content-type-options"), "nosniff");
      assert.equal(res.headers.get("x-frame-options"), "DENY");
      assert.match(res.headers.get("strict-transport-security") ?? "", /max-age=\d{7,}/);
    });
  }

  it("keeps the dashboard page's own nonce-based CSP instead of overwriting it", async () => {
    const { api } = makeApi();
    const csp = (await call(api, "GET", "/dashboard")).headers.get("content-security-policy") ?? "";
    assert.match(csp, /script-src 'nonce-/);
  });
});
