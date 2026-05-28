// AISeal F1+F2 — HMAC signing for the certification badge.
// Signs {cert_id, vendor_domain, score, issued_date} → HMAC-SHA256 → base64url.
// Embedded in the issued SVG (as XML comment + data attribute) AND validated by
// /api/verify/{cert_id}. Mismatch → forgery flag.
//
// Secret: AISEAL_BADGE_SECRET (env). Generate once:
//   node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))"
// Store in Railway env. NEVER expose to client — server-only.

import { createHmac } from "node:crypto";

export interface BadgePayload {
  cert_id: string;
  vendor_domain: string | null;
  score: number;
  issued_date: string;   // YYYY-MM-DD
}

function getSecret(): string {
  const s = process.env.AISEAL_BADGE_SECRET;
  if (!s || s.length < 32) {
    throw new Error(
      "AISEAL_BADGE_SECRET missing or too short (need ≥32 chars). Generate with: node -e \"console.log(require('node:crypto').randomBytes(32).toString('hex'))\"",
    );
  }
  return s;
}

/** Canonical signing string — order matters; never change without versioning. */
function canonical(p: BadgePayload): string {
  return [p.cert_id, p.vendor_domain ?? "", p.score, p.issued_date].join("|");
}

/** Returns base64url-encoded HMAC-SHA256, truncated to 22 chars (≈128 bits). */
export function signBadge(p: BadgePayload): string {
  const mac = createHmac("sha256", getSecret()).update(canonical(p)).digest("base64url");
  return mac.slice(0, 22);
}

/** Constant-time verification. Returns true iff signature matches the payload. */
export function verifyBadge(p: BadgePayload, signature: string): boolean {
  const expected = signBadge(p);
  if (expected.length !== signature.length) return false;
  // simple constant-time string compare
  let diff = 0;
  for (let i = 0; i < expected.length; i++) {
    diff |= expected.charCodeAt(i) ^ signature.charCodeAt(i);
  }
  return diff === 0;
}
