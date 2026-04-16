import { NextRequest, NextResponse } from "next/server";
import { rateLimit } from "@/app/lib/rate-limit";
import { runQRScan } from "@/lib/quantum";

const MAX_URL_LENGTH = 512;

// URL allowlist: only scan https:// public endpoints
function isAllowedTarget(raw: string): { ok: boolean; error?: string } {
  let url: URL;
  try {
    url = new URL(raw.startsWith("http") ? raw : `https://${raw}`);
  } catch {
    return { ok: false, error: "Invalid URL format" };
  }

  if (url.protocol !== "https:") {
    return { ok: false, error: "Only HTTPS endpoints can be scanned" };
  }

  const host = url.hostname.toLowerCase();

  // Block private/internal addresses
  const blocklist = [
    /^localhost$/,
    /^127\./,
    /^10\./,
    /^172\.(1[6-9]|2[0-9]|3[01])\./,
    /^192\.168\./,
    /^0\./,
    /^::1$/,
    /^fc[0-9a-f]{2}:/i,    // IPv6 ULA
  ];
  if (blocklist.some((p) => p.test(host))) {
    return { ok: false, error: "Private/internal addresses cannot be scanned" };
  }

  return { ok: true };
}

export async function POST(req: NextRequest) {
  const ip =
    req.headers.get("x-real-ip")?.trim() ??
    req.headers.get("x-forwarded-for")?.split(",").at(-1)?.trim() ??
    "unknown";

  const { ok: rateLimitOk } = rateLimit(ip, { maxRequests: 10, windowMs: 60_000 });
  if (!rateLimitOk) {
    return NextResponse.json(
      { error: "Rate limit exceeded. Quantum scans are limited to 10 per minute." },
      { status: 429 }
    );
  }

  let body: { target?: string; context?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const rawTarget = (body.target ?? "").trim().slice(0, MAX_URL_LENGTH);
  if (!rawTarget) {
    return NextResponse.json({ error: "target URL is required" }, { status: 400 });
  }

  const guard = isAllowedTarget(rawTarget);
  if (!guard.ok) {
    return NextResponse.json({ error: guard.error }, { status: 400 });
  }

  try {
    const result = await runQRScan(rawTarget);
    return NextResponse.json(result);
  } catch (err) {
    console.error("[QR Scan] Error:", err);
    return NextResponse.json(
      { error: "Scan failed. The target may be unreachable or blocking connections." },
      { status: 502 }
    );
  }
}
