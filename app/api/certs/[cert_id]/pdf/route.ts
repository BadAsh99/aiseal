// AISeal Certificate PDF download.
//
// GET /api/certs/{cert_id}/pdf
//   → application/pdf binary of a procurement-grade single-page cert.
//   → Includes the HMAC signature + a QR code linking to /api/verify/{cert_id}.
//     The QR/URL ties the PDF to the live registry so an auditor can confirm
//     the certificate is still active.
//
// 404 if cert_id doesn't exist. Cached for 5 min (cert content rarely changes;
// status drift is caught by the verify endpoint).

import { pdf } from "@react-pdf/renderer";
import QRCode from "qrcode";
import { getCertByCertId } from "../../../../../lib/registry";
import { signBadge } from "../../../../../lib/badge-hmac";
import { CertPdf } from "../../../../../lib/cert-pdf";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(
  _req: Request,
  { params }: { params: Promise<{ cert_id: string }> },
) {
  const { cert_id } = await params;

  let cert;
  try {
    cert = await getCertByCertId(cert_id);
  } catch (e) {
    return new Response(
      JSON.stringify({ error: "lookup_failed", message: e instanceof Error ? e.message : String(e) }),
      { status: 500, headers: { "content-type": "application/json" } },
    );
  }

  if (!cert) {
    return new Response(
      JSON.stringify({ error: "cert_not_found", cert_id }),
      { status: 404, headers: { "content-type": "application/json" } },
    );
  }

  const signature = signBadge({
    cert_id: cert.cert_id,
    vendor_domain: cert.vendor_domain,
    score: cert.trust_score,
    issued_date: cert.issued_date,
  });

  // QR encodes the verify URL — scanning it on a phone opens the live JSON
  // verification, which is the auditor's source of truth.
  const verifyUrl = `https://aiseal.ai/api/verify/${cert.cert_id}`;
  const qrDataUrl = await QRCode.toDataURL(verifyUrl, {
    errorCorrectionLevel: "M",
    margin: 1,
    width: 240,
    color: { dark: "#0f172a", light: "#ffffff" },
  });

  // Render PDF. @react-pdf/renderer's `pdf().toBuffer()` returns either a Buffer
  // or a Node ReadableStream depending on version. Normalize to ArrayBuffer
  // (BodyInit-compatible across TS Web type defs).
  const out = await pdf(CertPdf({ cert, signature, qrDataUrl })).toBuffer();

  let body: ArrayBuffer;
  if (Buffer.isBuffer(out)) {
    body = out.buffer.slice(out.byteOffset, out.byteOffset + out.byteLength) as ArrayBuffer;
  } else {
    const chunks: Buffer[] = [];
    for await (const chunk of out as AsyncIterable<Buffer>) {
      chunks.push(chunk);
    }
    const merged = Buffer.concat(chunks);
    body = merged.buffer.slice(merged.byteOffset, merged.byteOffset + merged.byteLength) as ArrayBuffer;
  }

  const filename = `AISeal-${cert.cert_id}.pdf`;
  return new Response(body, {
    status: 200,
    headers: {
      "content-type": "application/pdf",
      "content-disposition": `inline; filename="${filename}"`,
      "cache-control": "public, max-age=300, s-maxage=300",
      "access-control-allow-origin": "*",
    },
  });
}
