import { NextRequest, NextResponse } from "next/server";
import { randomUUID } from "crypto";
import { rateLimit } from "@/app/lib/rate-limit";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface RegistryApplication {
  application_id: string;
  submitted_at: string;
  company_name: string;
  contact_name: string;
  contact_email: string;
  product_name: string;
  product_version: string;
  website: string;
  industry: string;
  description: string;
  target_tier: string;
  frameworks: string[];
  how_heard: string;
}

// ---------------------------------------------------------------------------
// In-memory store (visible in Railway logs, ephemeral across deploys)
// ---------------------------------------------------------------------------

const applications = new Map<string, RegistryApplication>();

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function generateAppId(): string {
  const year = new Date().getFullYear();
  const suffix = Math.random().toString(36).slice(2, 6).toUpperCase();
  return `APP-${year}-${suffix}`;
}

function isValidEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isValidUrl(url: string): boolean {
  try {
    new URL(url.startsWith("http") ? url : `https://${url}`);
    return true;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// POST /api/registry/apply
// ---------------------------------------------------------------------------

export async function POST(req: NextRequest) {
  // Rate limit: 5 applications per IP per hour
  // Use x-real-ip (set by Railway/proxy) or the LAST entry in x-forwarded-for.
  // Never trust the FIRST x-forwarded-for entry — clients can spoof it to bypass rate limits.
  const ip =
    req.headers.get("x-real-ip")?.trim() ??
    req.headers.get("x-forwarded-for")?.split(",").at(-1)?.trim() ??
    "unknown";
  const { ok } = rateLimit(ip, { maxRequests: 5, windowMs: 60 * 60 * 1000 });
  if (!ok) {
    return NextResponse.json(
      { error: "Too many requests. Please try again later." },
      { status: 429 }
    );
  }

  let body: Record<string, unknown>;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid request body." }, { status: 400 });
  }

  // Validate required fields
  const required: (keyof typeof body)[] = [
    "company_name",
    "contact_name",
    "contact_email",
    "product_name",
    "industry",
    "description",
    "target_tier",
  ];

  for (const field of required) {
    if (!body[field] || String(body[field]).trim() === "") {
      return NextResponse.json({ error: `Missing required field: ${field}` }, { status: 400 });
    }
  }

  // Validate email
  const email = String(body.contact_email).trim();
  if (!isValidEmail(email)) {
    return NextResponse.json({ error: "Invalid contact email address." }, { status: 400 });
  }

  // Validate website if provided
  const website = String(body.website ?? "").trim();
  if (website && !isValidUrl(website)) {
    return NextResponse.json({ error: "Invalid website URL." }, { status: 400 });
  }

  // Validate tier
  const validTiers = ["ACF-1", "ACF-2", "ACF-3"];
  if (!validTiers.includes(String(body.target_tier))) {
    return NextResponse.json({ error: "Invalid target tier." }, { status: 400 });
  }

  // Validate industry
  const validIndustries = ["healthcare", "legal", "fintech", "hr-tech", "other"];
  if (!validIndustries.includes(String(body.industry))) {
    return NextResponse.json({ error: "Invalid industry." }, { status: 400 });
  }

  // Sanitize and truncate description
  const description = String(body.description).trim().slice(0, 2000);

  const application: RegistryApplication = {
    application_id: generateAppId(),
    submitted_at: new Date().toISOString(),
    company_name: String(body.company_name).trim().slice(0, 200),
    contact_name: String(body.contact_name).trim().slice(0, 200),
    contact_email: email.slice(0, 200),
    product_name: String(body.product_name).trim().slice(0, 200),
    product_version: String(body.product_version ?? "").trim().slice(0, 50),
    website: website.slice(0, 500),
    industry: String(body.industry),
    description,
    target_tier: String(body.target_tier),
    frameworks: Array.isArray(body.frameworks)
      ? body.frameworks.map(String).filter((f) =>
          ["OWASP", "NIST", "EU_AI_ACT", "MITRE"].includes(f)
        )
      : [],
    how_heard: String(body.how_heard ?? "").trim().slice(0, 500),
  };

  // Store in memory
  applications.set(application.application_id, application);

  // Log to console (visible in Railway deployment logs)
  console.log("[REGISTRY APPLICATION]", JSON.stringify(application, null, 2));

  // Optional: POST to a webhook (e.g., Zapier → Google Sheets or Slack)
  const webhookUrl = process.env.REGISTRY_NOTIFY_WEBHOOK;
  if (webhookUrl) {
    fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(application),
    }).catch((err) => {
      console.error("[REGISTRY WEBHOOK ERROR]", err);
    });
  }

  return NextResponse.json(
    {
      success: true,
      application_id: application.application_id,
      message:
        "Your certification application has been received. We'll review it and reach out within 5 business days.",
    },
    { status: 201 }
  );
}

// ---------------------------------------------------------------------------
// GET /api/registry/apply — admin listing (requires secret header)
// ---------------------------------------------------------------------------

export async function GET(req: NextRequest) {
  const secret = process.env.REGISTRY_ADMIN_SECRET;
  if (!secret || req.headers.get("x-admin-secret") !== secret) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const list = Array.from(applications.values()).sort(
    (a, b) => new Date(b.submitted_at).getTime() - new Date(a.submitted_at).getTime()
  );

  return NextResponse.json({ count: list.length, applications: list });
}
