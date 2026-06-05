import { describe, it, expect } from "vitest";
import { signBadge, verifyBadge, type BadgePayload } from "@/lib/badge-hmac";

// The cert badge HMAC is what makes an AISeal certification forgery-resistant —
// verify() must accept a genuine signature and reject any tampering.
const payload: BadgePayload = {
  cert_id: "ACF3-2026-0001",
  vendor_domain: "example.com",
  score: 94,
  issued_date: "2026-06-05",
};

describe("badge-hmac · cert forgery resistance", () => {
  it("signs and verifies a genuine badge (roundtrip)", () => {
    const sig = signBadge(payload);
    expect(sig).toHaveLength(22);
    expect(verifyBadge(payload, sig)).toBe(true);
  });

  it("rejects a tampered signature", () => {
    const sig = signBadge(payload);
    const tampered = sig.slice(0, -1) + (sig.at(-1) === "A" ? "B" : "A");
    expect(verifyBadge(payload, tampered)).toBe(false);
  });

  it("rejects a forged payload (score bumped) reusing the old signature", () => {
    const sig = signBadge(payload);
    expect(verifyBadge({ ...payload, score: 100 }, sig)).toBe(false);
  });

  it("rejects a wrong-length signature", () => {
    expect(verifyBadge(payload, "short")).toBe(false);
  });
});
