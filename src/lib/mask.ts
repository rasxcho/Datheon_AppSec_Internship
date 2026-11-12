/**
 * PII masking for public payloads (Task 4). Pure functions, no I/O, so they are trivial to unit test.
 * Rule of thumb: a verifier should be able to CONFIRM a record they already hold, never DISCOVER one.
 */

/** alice@example.com -> a***e@example.com ; ab@x.org -> a***@x.org ; invalid input -> *** */
export function maskEmail(email: string): string {
  const at = email.lastIndexOf("@");
  if (at < 1 || at === email.length - 1) return "***";
  const local = email.slice(0, at);
  const domain = email.slice(at + 1);
  if (local.length <= 2) return `${local[0]}***@${domain}`;
  return `${local[0]}***${local[local.length - 1]}@${domain}`;
}

/** "+91 90000 00001" -> "+** ***** ***01": every digit hidden except the last two, separators kept. */
export function maskPhone(phone: string): string {
  const totalDigits = (phone.match(/\d/g) ?? []).length;
  if (totalDigits === 0) return "***";
  let seen = 0;
  return phone.replace(/\d/g, (d) => {
    seen += 1;
    return totalDigits > 4 && seen > totalDigits - 2 ? d : "*";
  });
}

/** "Alice Kumar" -> "A*** K***" (initial only, fixed-width stars so the length leaks nothing). */
export function maskName(name: string): string {
  const parts = name.trim().split(/\s+/).filter(Boolean);
  if (parts.length === 0) return "***";
  return parts.map((p) => `${p[0]}***`).join(" ");
}
