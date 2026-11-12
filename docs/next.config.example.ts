// How the Task 4 headers map onto a Next.js app (App Router). Not compiled in this lab; copy into next.config.ts.
import type { NextConfig } from "next";

const securityHeaders = [
  { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Referrer-Policy", value: "no-referrer" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), payment=()" },
  { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
  // API responses: nothing should load. For HTML pages, set a nonce-based CSP in middleware.ts instead.
  { key: "Content-Security-Policy", value: "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'" },
];

const config: NextConfig = {
  poweredByHeader: false, // do not advertise the framework
  async headers() {
    return [{ source: "/api/:path*", headers: securityHeaders }];
  },
};

export default config;
