const BASE_HEADERS: Record<string, string> = {
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "no-store", // never let a proxy or browser cache personal data
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
};

export interface ResponseOptions {
  headers?: Record<string, string>;
  cookies?: string[];
}

export function json(status: number, body: unknown, options: ResponseOptions = {}): Response {
  const headers = new Headers({ ...BASE_HEADERS, ...options.headers });
  for (const cookie of options.cookies ?? []) headers.append("Set-Cookie", cookie);
  return new Response(JSON.stringify(body), { status, headers });
}

/** The adapter in server.ts overwrites this header with the real socket address (never trust client-supplied values). */
export const clientIp = (request: Request): string => request.headers.get("x-client-ip") ?? "unknown";

export async function readJson(request: Request): Promise<Record<string, unknown> | null> {
  try {
    const text = await request.text();
    if (text.length > 10_000) return null;
    const parsed: unknown = JSON.parse(text);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

export function html(status: number, body: string, headers: Record<string, string> = {}): Response {
  return new Response(body, {
    status,
    headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", ...headers },
  });
}
