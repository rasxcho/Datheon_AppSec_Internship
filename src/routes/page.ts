/**
 * Minimal dashboard front end. The page itself contains NO personal data: it reads ?appId= from the URL
 * and calls the API with fetch(). That is the "client-side routing" pattern from Task 1 - the browser
 * decides which record to request, so only the API can enforce who may see it.
 *
 * Output is written with textContent (no innerHTML) and a nonce-based CSP, so the page is not an XSS risk.
 */
import { randomBytes } from "node:crypto";
import { html } from "../lib/http.js";

export function dashboardPage(apiPath: string, title: string) {
  return async function GET(): Promise<Response> {
    const nonce = randomBytes(16).toString("base64");
    const csp = [
      "default-src 'none'",
      `script-src 'nonce-${nonce}'`,
      `style-src 'nonce-${nonce}'`,
      "connect-src 'self'",
      "base-uri 'none'",
      "form-action 'none'",
      "frame-ancestors 'none'",
    ].join("; ");

    const body = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title}</title>
<style nonce="${nonce}">body{font:16px system-ui;margin:2rem;max-width:36rem}th{text-align:left;padding-right:1rem}#msg{color:#555}</style>
</head><body>
<h1>${title}</h1>
<p id="msg">Loading...</p>
<table id="rec" hidden></table>
<script nonce="${nonce}">
  const appId = new URLSearchParams(location.search).get("appId") || "DT-2026-001";
  fetch(${JSON.stringify(apiPath)} + "?appId=" + encodeURIComponent(appId), { credentials: "same-origin" })
    .then(async (r) => ({ status: r.status, body: await r.json().catch(() => ({})) }))
    .then(({ status, body }) => {
      const msg = document.getElementById("msg");
      if (status !== 200) { msg.textContent = "Cannot show this record (HTTP " + status + ")."; return; }
      msg.textContent = "Application " + appId;
      const table = document.getElementById("rec");
      for (const [k, v] of Object.entries(body)) {
        const row = table.insertRow();
        row.insertCell().textContent = k;
        row.insertCell().textContent = String(v);
      }
      table.hidden = false;
    })
    .catch(() => { document.getElementById("msg").textContent = "Network error."; });
</script></body></html>`;
    return html(200, body, { "Content-Security-Policy": csp });
  };
}
