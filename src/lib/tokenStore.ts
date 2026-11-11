/** Tracks revoked token ids (logout, rotation). Entries expire with the token, so the set stays small. */
export class TokenStore {
  private readonly revoked = new Map<string, number>(); // jti -> exp (seconds)

  revoke(jti: string, expSeconds: number, nowMs: number): void {
    this.revoked.set(jti, expSeconds);
    for (const [id, exp] of this.revoked) if (exp * 1000 <= nowMs) this.revoked.delete(id);
  }

  isRevoked(jti: string): boolean {
    return this.revoked.has(jti);
  }
}
