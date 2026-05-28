// AISeal F1+F2 — public certificate verification endpoint.
//
// GET /api/verify/{cert_id}
//   → 200 { valid: true, ...cert details, origin_check, signature, verified_at }
//   → 404 { valid: false, result: "cert_not_found" }
//
// Validates the calling Origin/Referer against the certified vendor_domain when
// present (Pilot certs have no vendor_domain — those return origin_check="pilot_vendor").
// Every call is logged to verification_log so we can surface "live verification
// activity" + detect badge-forgery attempts (origin_mismatch).
//
// The HMAC signature is included so the badge SVG's embedded signature can be
// cross-checked: caller fetches /api/verify/{cert_id}, compares its returned
// signature to the one in the badge — if they match, the badge wasn't altered.

import { NextResponse } from "next/server";
import { getCertByCertId } from "../../../../lib/registry";
import { signBadge } from "../../../../lib/badge-hmac";
import { supabaseAdmin } from "../../../../lib/supabase/server";
import { createHash } from "node:crypto";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

type VerifyResult = "verified" | "origin_mismatch" | "no_origin" | "cert_not_found" | "cert_inactive";

function ipFromHeaders(req: Request): string {
  // Use last x-forwarded-for entry / x-real-ip — same hardened pattern as
  // /api/registry/apply (per the AISeal audit 2026-05-27 Tier-1 item).
  const xff = req.headers.get("x-forwarded-for");
  if (xff) {
    const parts = xff.split(",").map((p) => p.trim()).filter(Boolean);
    if (parts.length > 0) return parts[parts.length - 1];
  }
  const xri = req.headers.get("x-real-ip");
  if (xri) return xri.trim();
  return "unknown";
}

function hashIp(ip: string): string {
  return createHash("sha256").update(ip).digest("hex").slice(0, 32);
}

/** Normalize a candidate origin/host to a bare hostname for comparison. */
function toHost(s: string | null | undefined): string | null {
  if (!s) return null;
  try {
    return new URL(s.startsWith("http") ? s : `https://${s}`).hostname.toLowerCase();
  } catch {
    return s.toLowerCase().trim();
  }
}

async function logCall(args: {
  cert_id: string | null;
  origin: string | null;
  referer: string | null;
  result: VerifyResult;
  ip_hash: string;
  user_agent: string | null;
}) {
  try {
    await supabaseAdmin().from("verification_log").insert(args);
  } catch {
    // Logging must never break the call path — fail open and silently.
  }
}

export async function GET(
  req: Request,
  { params }: { params: Promise<{ cert_id: string }> },
) {
  const { cert_id } = await params;
  const origin = req.headers.get("origin");
  const referer = req.headers.get("referer");
  const user_agent = req.headers.get("user-agent")?.slice(0, 300) ?? null;
  const ip_hash = hashIp(ipFromHeaders(req));

  // 1. Look up cert
  let cert;
  try {
    cert = await getCertByCertId(cert_id);
  } catch (e) {
    // DB error — return 500 but don't leak details
    return NextResponse.json(
      { valid: false, result: "lookup_failed", message: String(e instanceof Error ? e.message : e) },
      { status: 500 },
    );
  }

  if (!cert) {
    await logCall({ cert_id, origin, referer, result: "cert_not_found", ip_hash, user_agent });
    return NextResponse.json({ valid: false, result: "cert_not_found", cert_id }, { status: 404 });
  }

  // 2. Compute HMAC signature
  const signature = signBadge({
    cert_id: cert.cert_id,
    vendor_domain: cert.vendor_domain,
    score: cert.trust_score,
    issued_date: cert.issued_date,
  });

  // 3. Status check (suspended/expired are still verifiable but flagged)
  if (cert.status !== "ACTIVE") {
    await logCall({ cert_id, origin, referer, result: "cert_inactive", ip_hash, user_agent });
  }

  // 4. Origin / Referer check
  let origin_check: "ok" | "no_origin" | "origin_mismatch" | "pilot_vendor" = "no_origin";
  let final_result: VerifyResult = cert.status === "ACTIVE" ? "verified" : "cert_inactive";

  if (cert.vendor_domain === null) {
    origin_check = "pilot_vendor"; // demo/seed cert, no domain bound
  } else {
    const callerHost = toHost(origin) ?? toHost(referer);
    const certHost = cert.vendor_domain.toLowerCase().trim();
    if (!callerHost) {
      origin_check = "no_origin";
    } else if (callerHost === certHost || callerHost.endsWith(`.${certHost}`)) {
      origin_check = "ok";
    } else {
      origin_check = "origin_mismatch";
      final_result = "origin_mismatch";
      await logCall({ cert_id, origin, referer, result: "origin_mismatch", ip_hash, user_agent });
    }
  }

  // Log the verified call (idempotent — we may have also logged a non-"verified" result above)
  if (final_result === "verified") {
    await logCall({ cert_id, origin, referer, result: "verified", ip_hash, user_agent });
  }

  return NextResponse.json(
    {
      valid: final_result === "verified",
      result: final_result,
      cert: {
        cert_id: cert.cert_id,
        vendor_id: cert.vendor_id,
        vendor_name: cert.vendor_name,
        vendor_domain: cert.vendor_domain,
        product_name: cert.product_name,
        product_version: cert.product_version,
        tier: cert.tier,
        status: cert.status,
        trust_score: cert.trust_score,
        issued_date: cert.issued_date,
        expiry_date: cert.expiry_date,
        frameworks: cert.frameworks,
      },
      origin_check,
      signature,
      registry_url: `https://aiseal.ai/registry/${cert.vendor_id}`,
      verified_at: new Date().toISOString(),
    },
    {
      headers: {
        "cache-control": "public, max-age=60",  // short cache; verification freshness matters
      },
    },
  );
}
