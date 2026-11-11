import { randomBytes, scryptSync, timingSafeEqual } from "node:crypto";

/** scrypt with a per-password random salt. Format: saltHex:hashHex */
export function hashPassword(password: string): string {
  const salt = randomBytes(16);
  return `${salt.toString("hex")}:${scryptSync(password, salt, 64).toString("hex")}`;
}

export function verifyPassword(password: string, stored: string): boolean {
  const [saltHex, hashHex] = stored.split(":");
  if (!saltHex || !hashHex) return false;
  const expected = Buffer.from(hashHex, "hex");
  const actual = scryptSync(password, Buffer.from(saltHex, "hex"), expected.length);
  return timingSafeEqual(actual, expected);
}

/** Verified against when the account does not exist, so response time does not reveal valid emails. */
export const DUMMY_HASH = hashPassword("dummy-password-for-timing");
