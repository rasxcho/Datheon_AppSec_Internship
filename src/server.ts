/** Thin Node adapter: turns http requests into Web Request objects for the router. Run: npm start */
import { createServer } from "node:http";
import { createDeps } from "./lib/deps.js";
import { createRouter } from "./router.js";

const deps = createDeps();
const route = createRouter(deps);
const port = Number(process.env.PORT ?? 3000);
const MAX_BODY = 10_000;

const server = createServer(async (req, res) => {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > MAX_BODY) { res.writeHead(413).end(); return; }
    chunks.push(chunk as Buffer);
  }

  const headers = new Headers();
  for (const [name, value] of Object.entries(req.headers)) {
    if (name === "x-client-ip") continue; // never trust a client-supplied value
    if (Array.isArray(value)) value.forEach((v) => headers.append(name, v)); else if (value !== undefined) headers.set(name, value);
  }
  headers.set("x-client-ip", req.socket.remoteAddress ?? "unknown"); // behind a proxy, use the proxy's trusted header instead

  const hasBody = !["GET", "HEAD"].includes(req.method ?? "GET");
  const request = new Request(`http://${req.headers.host ?? "localhost"}${req.url ?? "/"}`, {
    method: req.method,
    headers,
    body: hasBody ? Buffer.concat(chunks) : undefined,
  });

  const response = await route(request);
  const out: Record<string, string | string[]> = {};
  response.headers.forEach((value, name) => { if (name !== "set-cookie") out[name] = value; });
  const cookies = response.headers.getSetCookie();
  if (cookies.length) out["set-cookie"] = cookies;
  res.writeHead(response.status, out).end(await response.text());
});

server.listen(port, "127.0.0.1", () => {
  console.log(`API listening on http://127.0.0.1:${port}  (vulnerable lab route: ${deps.enableVulnerableLab ? "ON" : "off"})`);
});
