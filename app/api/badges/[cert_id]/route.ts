// AISeal F1+F2 — self-hosted HMAC-signed certification badge.
//
// GET /api/badges/{cert_id}.svg  (or /api/badges/{cert_id})
//   → SVG image of the badge, with the HMAC signature embedded in:
//     1. An XML comment at the top of the SVG source
//     2. A data-signature attribute on the root <svg>
//   → cert_id not found returns a "INVALID" SVG so embeds fail visibly.
//
// This replaces the prior forgeable shields.io PNG. Verifiers cross-check the
// signature against /api/verify/{cert_id} — if the badge was altered, the
// signatures won't match.

import { getCertByCertId, type CertTier } from "../../../../lib/registry";
import { signBadge } from "../../../../lib/badge-hmac";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const TIER_COLOR: Record<CertTier, { main: string; dark: string; label: string }> = {
  "ACF-1": { main: "#00c853", dark: "#007a32", label: "Verified" },
  "ACF-2": { main: "#0080ff", dark: "#0057b3", label: "Assured" },
  "ACF-3": { main: "#d4a017", dark: "#8c6a0a", label: "Certified" },
};

function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function invalidBadge(cert_id: string): string {
  return `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="240" height="60" viewBox="0 0 240 60" role="img" aria-label="AISeal — Invalid Certificate">
  <rect width="240" height="60" fill="#1a1a1a"/>
  <rect width="6" height="60" fill="#dc2626"/>
  <text x="20" y="25" font-family="-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif" font-size="11" font-weight="700" fill="#dc2626">AISEAL — INVALID</text>
  <text x="20" y="42" font-family="monospace" font-size="9" fill="#9ca3af">${esc(cert_id)}</text>
  <text x="20" y="54" font-family="monospace" font-size="8" fill="#6b7280">cert_id not found</text>
</svg>`;
}

function svgBadge(opts: {
  vendor_name: string;
  cert_id: string;
  tier: CertTier;
  score: number;
  vendor_id: string;
  signature: string;
  issued_date: string;
  registry_url: string;
}): string {
  const { vendor_name, cert_id, tier, score, signature, issued_date, registry_url } = opts;
  const c = TIER_COLOR[tier];
  // Truncate vendor name to fit
  const name = vendor_name.length > 22 ? vendor_name.slice(0, 21) + "…" : vendor_name;
  return `<?xml version="1.0" encoding="UTF-8"?>
<!--
  AISeal Certification Badge — HMAC-signed
  cert_id:    ${cert_id}
  tier:       ${tier}
  score:      ${score}
  issued:     ${issued_date}
  signature:  ${signature}
  verify:     https://aiseal.ai/api/verify/${cert_id}
-->
<svg xmlns="http://www.w3.org/2000/svg"
     width="240" height="60" viewBox="0 0 240 60"
     role="img" aria-label="AISeal ${tier} Certified — ${esc(vendor_name)} TrustScore ${score}"
     data-aiseal-cert-id="${esc(cert_id)}"
     data-aiseal-tier="${tier}"
     data-aiseal-score="${score}"
     data-aiseal-signature="${signature}"
     data-aiseal-verify="${esc(registry_url)}">
  <a href="${esc(registry_url)}" target="_blank" rel="noopener noreferrer">
    <rect width="240" height="60" fill="#0f1419" rx="6"/>
    <rect width="6" height="60" fill="${c.main}" rx="6"/>
    <!-- AISeal mark -->
    <g transform="translate(18,12)">
      <path d="M12 0 L1 4 V12 C1 18 5 23 12 25 C19 23 23 18 23 12 V4 L12 0 Z"
            fill="${c.main}" fill-opacity="0.18" stroke="${c.main}" stroke-width="1.4"/>
      <path d="M8 12 L11 15 L17 9" fill="none" stroke="${c.main}" stroke-width="1.6"
            stroke-linecap="round" stroke-linejoin="round"/>
    </g>
    <text x="50" y="22" font-family="-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif" font-size="11" font-weight="700" fill="#ffffff" letter-spacing="0.2">AISeal</text>
    <text x="50" y="34" font-family="-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif" font-size="9" font-weight="600" fill="${c.main}" letter-spacing="0.4">${tier} · ${c.label.toUpperCase()}</text>
    <text x="50" y="50" font-family="-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif" font-size="9" fill="#9ca3af">${esc(name)}</text>
    <!-- TrustScore on right -->
    <g transform="translate(178,8)">
      <rect width="48" height="44" rx="6" fill="${c.dark}" fill-opacity="0.55"/>
      <text x="24" y="20" text-anchor="middle" font-family="-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif" font-size="8" font-weight="600" fill="#ffffff" letter-spacing="0.5">SCORE</text>
      <text x="24" y="38" text-anchor="middle" font-family="-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif" font-size="18" font-weight="800" fill="#ffffff">${score}</text>
    </g>
  </a>
</svg>`;
}

export async function GET(
  _req: Request,
  { params }: { params: Promise<{ cert_id: string }> },
) {
  const raw = (await params).cert_id;
  // Allow /api/badges/{cert_id}.svg or /api/badges/{cert_id}
  const cert_id = raw.endsWith(".svg") ? raw.slice(0, -4) : raw;

  let cert;
  try {
    cert = await getCertByCertId(cert_id);
  } catch {
    cert = null;
  }

  if (!cert) {
    return new Response(invalidBadge(cert_id), {
      status: 404,
      headers: {
        "content-type": "image/svg+xml; charset=utf-8",
        "cache-control": "public, max-age=60",
      },
    });
  }

  const signature = signBadge({
    cert_id: cert.cert_id,
    vendor_domain: cert.vendor_domain,
    score: cert.trust_score,
    issued_date: cert.issued_date,
  });

  const svg = svgBadge({
    vendor_name: cert.vendor_name,
    cert_id: cert.cert_id,
    tier: cert.tier,
    score: cert.trust_score,
    vendor_id: cert.vendor_id,
    signature,
    issued_date: cert.issued_date,
    registry_url: `https://aiseal.ai/registry/${cert.vendor_id}`,
  });

  return new Response(svg, {
    status: 200,
    headers: {
      "content-type": "image/svg+xml; charset=utf-8",
      // 5-min CDN cache; if score/tier changes, badge auto-refreshes in 5 min
      "cache-control": "public, max-age=300, s-maxage=300",
      // Allow embedding cross-origin (badges live on vendor sites)
      "access-control-allow-origin": "*",
    },
  });
}
