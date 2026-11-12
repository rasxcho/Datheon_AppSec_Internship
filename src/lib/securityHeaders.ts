/**
 * Baseline security headers applied to EVERY response by the router (including 404/405/500),
 * so no individual handler can forget them. A handler may set its own value (the HTML page sets a
 * nonce-based CSP); applySecurityHeaders only fills in what is missing.
 */
export const SECURITY_HEADERS: Readonly<Record<string, string>> = {
  // JSON API: nothing here should ever load or execute anything.
  "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
  // Two years + subdomains. Browsers ignore HSTS on plain http, so it is harmless on the local lab.
  "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Cross-Origin-Opener-Policy": "same-origin",
};

export function applySecurityHeaders(response: Response): Response {
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
    if (!response.headers.has(name)) response.headers.set(name, value);
  }
  return response;
}
