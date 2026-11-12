/**
 * GET /api/public/verify?certId=DT-CERT-7F3K9Q2M   (public, no login - Task 4)
 *
 * Zero-leakage design:
 *   - allow-list response: fields are copied one by one, so a new column added to the table can never leak
 *   - PII is masked (name, email, phone); internal ids (appId, ownerEmail) are never returned
 *   - strict id format, uniform 404 for "unknown" and "malformed" so the endpoint is not an existence oracle
 *   - revoked certificates return only { valid:false, status }, no holder details at all
 *   - throttled per IP (separate bucket from the authenticated lookup)
 */
import { clientIp, json } from "../lib/http.js";
import type { Deps } from "../lib/deps.js";
import { maskEmail, maskName, maskPhone } from "../lib/mask.js";
import { rateLimitHeaders } from "../lib/rateLimit.js";

const CERT_ID_PATTERN = /^DT-CERT-[A-Z0-9]{8}$/;

export function publicVerifyHandler(deps: Deps) {
  return async function GET(request: Request): Promise<Response> {
    const limit = deps.lookupLimiter.check(`public:${clientIp(request)}`);
    const headers = { ...rateLimitHeaders(limit), "Cache-Control": "public, max-age=60" };
    if (!limit.allowed) return json(429, { error: "Too many requests" }, { headers: { ...headers, "Cache-Control": "no-store" } });

    const certId = new URL(request.url).searchParams.get("certId") ?? "";
    const cert = CERT_ID_PATTERN.test(certId) ? deps.db.findCertificate(certId) : undefined;
    const holder = cert ? deps.db.findByAppId(cert.appId) : undefined;
    if (!cert || !holder) return json(404, { valid: false, error: "Not found" }, { headers: { ...headers, "Cache-Control": "no-store" } });

    if (cert.status === "revoked") return json(200, { valid: false, certificateId: cert.certId, status: "revoked" }, { headers });

    return json(
      200,
      {
        valid: true,
        certificateId: cert.certId,
        status: cert.status,
        program: cert.program,
        issuedOn: cert.issuedOn,
        holder: maskName(holder.name),
        email: maskEmail(holder.email),
        phone: maskPhone(holder.phone),
      },
      { headers },
    );
  };
}
