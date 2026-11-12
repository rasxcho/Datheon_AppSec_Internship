import { hashPassword } from "./password.js";

export interface Student {
  appId: string;
  ownerEmail: string; // the account that owns this record
  name: string;
  email: string;
  phone: string;
  notes: string;
}

export interface Certificate {
  certId: string;      // public, unguessable-enough identifier printed on the certificate
  appId: string;       // internal link to the student record - never returned publicly
  program: string;
  issuedOn: string;
  status: "issued" | "revoked";
}

export interface User {
  email: string;
  role: "student" | "staff";
  passwordHash: string;
}

/** In-memory stand-in for a real database. All data is fictional. */
export class Database {
  constructor(readonly students: Student[], readonly users: User[], readonly certificates: Certificate[] = []) {}

  /** UNSAFE pattern: any caller-supplied id reads any row. Used by the vulnerable lab route only. */
  findByAppId(appId: string): Student | undefined {
    return this.students.find((s) => s.appId === appId);
  }

  /** SAFE pattern: SELECT ... WHERE app_id = $1 AND owner_email = $2 */
  findByAppIdForOwner(appId: string, ownerEmail: string): Student | undefined {
    return this.students.find((s) => s.appId === appId && s.ownerEmail === ownerEmail);
  }

  findCertificate(certId: string): Certificate | undefined {
    return this.certificates.find((c) => c.certId === certId);
  }

  findUser(email: string): User | undefined {
    return this.users.find((u) => u.email === email);
  }
}

export const LAB_PASSWORDS = { "alice@example.com": "Alice#Lab-2026", "bob@example.com": "Bob#Lab-2026!" } as const;

export function seedDatabase(): Database {
  return new Database(
    [
      { appId: "DT-2026-001", ownerEmail: "alice@example.com", name: "Alice Kumar", email: "alice@example.com", phone: "+91 90000 00001", notes: "Shortlisted for AppSec track" },
      { appId: "DT-2026-002", ownerEmail: "bob@example.com", name: "Bob Raman", email: "bob@example.com", phone: "+91 90000 00002", notes: "Needs resubmission of ID proof" },
      { appId: "DT-2026-003", ownerEmail: "carol@example.com", name: "Carol Nair", email: "carol@example.com", phone: "+91 90000 00003", notes: "Scholarship applicant" },
      { appId: "DT-2026-004", ownerEmail: "dev@example.com", name: "Dev Menon", email: "dev@example.com", phone: "+91 90000 00004", notes: "Referred by faculty" },
      { appId: "DT-2026-005", ownerEmail: "esha@example.com", name: "Esha Iyer", email: "esha@example.com", phone: "+91 90000 00005", notes: "Interview scheduled" },
    ],
    [
      { email: "alice@example.com", role: "student", passwordHash: hashPassword(LAB_PASSWORDS["alice@example.com"]) },
      { email: "bob@example.com", role: "student", passwordHash: hashPassword(LAB_PASSWORDS["bob@example.com"]) },
    ],
    [
      { certId: "DT-CERT-7F3K9Q2M", appId: "DT-2026-001", program: "Application Security Internship", issuedOn: "2026-10-01", status: "issued" },
      { certId: "DT-CERT-4B8N1X6D", appId: "DT-2026-002", program: "Application Security Internship", issuedOn: "2026-10-01", status: "issued" },
      { certId: "DT-CERT-9H2T5W0R", appId: "DT-2026-003", program: "Application Security Internship", issuedOn: "2026-10-01", status: "revoked" },
    ],
  );
}
