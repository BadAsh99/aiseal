// AISeal F1+F2 — certification application intake.
//
// POST /api/registry/apply  → inserts into public.applications (RLS-on, NO anon
//   policy — service-role only). Replaces the prior in-memory Map that wiped on
//   every Railway deploy.
// GET  /api/registry/apply  → admin listing (x-admin-secret header required).
//
// PII (email, ip_hash, user_agent) is isolated in this table by design — the
// public certifications table NEVER joins to it. That's the physical-separation
// pattern from the 2026-05-27 RLS lesson.

import { NextRequest, NextResponse } from "next/server";
import { createHash } from "node:crypto";
import { rateLimit } from "@/app/lib/rate-limit";
import { supabaseAdmin } from "../../../../lib/supabase/server";
import { escapeMrkdwn } from "../../../../lib/slack-escape";

interface ApplicationRow {
  id: string;
  created_at: string;
  email: string;
  company_name: string;
  vendor_domain: string | null;
  product_name: string;
  product_version: string | null;
  tier_requested: "ACF-1" | "ACF-2" | "ACF-3";
  industry: "healthcare" | "legal" | "fintech" | "hr-tech" | "other";
  description: string | null;
  how_heard: string | null;
  notes: Record<string, unknown>;
  status: "pending" | "approved" | "rejected" | "withdrawn";
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

function extractDomain(url: string): string | null {
  try {
    return new URL(url.startsWith("http") ? url : `https://${url}`).hostname.toLowerCase();
  } catch {
    return null;
  }
}

function ipFromHeaders(req: NextRequest): string {
  // Last x-forwarded-for / x-real-ip — never trust the first XFF entry
  // (clients can spoof it to bypass rate limits).
  const xff = req.headers.get("x-forwarded-for");
  if (xff) {
    const parts = xff.split(",").map((p) => p.trim()).filter(Boolean);
    if (parts.length > 0) return parts[parts.length - 1];
  }
  return req.headers.get("x-real-ip")?.trim() ?? "unknown";
}

function hashIp(ip: string): string {
  return createHash("sha256").update(ip).digest("hex").slice(0, 32);
}

// ---------------------------------------------------------------------------
// POST /api/registry/apply
// ---------------------------------------------------------------------------

export async function POST(req: NextRequest) {
  const ip = ipFromHeaders(req);
  const { ok } = rateLimit(ip, { maxRequests: 5, windowMs: 60 * 60 * 1000 });
  if (!ok) {
    return NextResponse.json(
      { error: "Too many requests. Please try again later." },
      { status: 429 },
    );
  }

  let body: Record<string, unknown>;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid request body." }, { status: 400 });
  }

  const required = [
    "company_name",
    "contact_name",
    "contact_email",
    "product_name",
    "industry",
    "description",
    "target_tier",
  ] as const;

  for (const field of required) {
    if (!body[field] || String(body[field]).trim() === "") {
      return NextResponse.json({ error: `Missing required field: ${field}` }, { status: 400 });
    }
  }

  const email = String(body.contact_email).trim();
  if (!isValidEmail(email)) {
    return NextResponse.json({ error: "Invalid contact email address." }, { status: 400 });
  }

  const website = String(body.website ?? "").trim();
  if (website && !isValidUrl(website)) {
    return NextResponse.json({ error: "Invalid website URL." }, { status: 400 });
  }

  const validTiers = ["ACF-1", "ACF-2", "ACF-3"] as const;
  const tier_requested = String(body.target_tier) as (typeof validTiers)[number];
  if (!validTiers.includes(tier_requested)) {
    return NextResponse.json({ error: "Invalid target tier." }, { status: 400 });
  }

  const validIndustries = ["healthcare", "legal", "fintech", "hr-tech", "other"] as const;
  const industry = String(body.industry) as (typeof validIndustries)[number];
  if (!validIndustries.includes(industry)) {
    return NextResponse.json({ error: "Invalid industry." }, { status: 400 });
  }

  const company_name = String(body.company_name).trim().slice(0, 200);
  const product_name = String(body.product_name).trim().slice(0, 200);
  const product_version = String(body.product_version ?? "").trim().slice(0, 50) || null;
  const description = String(body.description).trim().slice(0, 2000);
  const how_heard = String(body.how_heard ?? "").trim().slice(0, 500) || null;
  const contact_name = String(body.contact_name).trim().slice(0, 200);
  const vendor_domain = website ? extractDomain(website) : null;

  const frameworks = Array.isArray(body.frameworks)
    ? body.frameworks
        .map(String)
        .filter((f) => ["OWASP", "NIST", "EU_AI_ACT", "MITRE"].includes(f))
    : [];

  const ip_hash = hashIp(ip);
  const user_agent = req.headers.get("user-agent")?.slice(0, 300) ?? null;

  const db = supabaseAdmin();
  const { data, error } = await db
    .from("applications")
    .insert({
      email: email.slice(0, 200),
      company_name,
      vendor_domain,
      product_name,
      product_version,
      tier_requested,
      industry,
      description,
      how_heard,
      notes: {
        contact_name,
        website: website.slice(0, 500) || null,
        frameworks,
      },
      ip_hash,
      user_agent,
    })
    .select("id, created_at")
    .single();

  if (error || !data) {
    console.error("[REGISTRY APPLICATION] insert failed", error);
    return NextResponse.json(
      { error: "Could not save your application. Please try again or email cert@aiseal.ai." },
      { status: 500 },
    );
  }

  console.log("[REGISTRY APPLICATION]", data.id, company_name, tier_requested);

  // Fire Slack notification (non-blocking)
  const webhookUrl = process.env.REGISTRY_NOTIFY_WEBHOOK;
  if (webhookUrl) {
    const tierEmoji: Record<string, string> = {
      "ACF-1": "🔘", "ACF-2": "🔵", "ACF-3": "🟡",
    };
    const industryLabel: Record<string, string> = {
      healthcare: "Healthcare", legal: "Legal", fintech: "Fintech",
      "hr-tech": "HR Tech", other: "Other",
    };
    const frameworkList = frameworks.length ? frameworks.join(", ") : "OWASP only";

    const slackPayload = {
      blocks: [
        {
          type: "header",
          text: { type: "plain_text", text: "🟢 New AISeal Certification Application", emoji: true },
        },
        {
          type: "section",
          fields: [
            // F12 fix — escape all user-supplied fields before mrkdwn interpolation
            { type: "mrkdwn", text: `*Company*\n${escapeMrkdwn(company_name)}` },
            { type: "mrkdwn", text: `*Product*\n${escapeMrkdwn(product_name)}${product_version ? " " + escapeMrkdwn(product_version) : ""}` },
            { type: "mrkdwn", text: `*Contact*\n${escapeMrkdwn(contact_name)}` },
            { type: "mrkdwn", text: `*Email*\n${escapeMrkdwn(email)}` },
            { type: "mrkdwn", text: `*Industry*\n${industryLabel[industry] ?? industry}` },
            { type: "mrkdwn", text: `*Target Tier*\n${tierEmoji[tier_requested] ?? ""} ${tier_requested}` },
          ],
        },
        {
          type: "section",
          fields: [
            { type: "mrkdwn", text: `*Frameworks*\n${frameworkList}` },
            { type: "mrkdwn", text: `*How they found us*\n${escapeMrkdwn(how_heard || "not specified")}` },
          ],
        },
        {
          type: "section",
          text: {
            type: "mrkdwn",
            text: `*What their AI does*\n${escapeMrkdwn(description.slice(0, 300))}${description.length > 300 ? "…" : ""}`,
          },
        },
        { type: "divider" },
        {
          type: "context",
          elements: [
            {
              type: "mrkdwn",
              text: `Application ID: \`${data.id}\` · ${new Date(data.created_at).toLocaleString("en-US", { timeZone: "America/Phoenix", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })} AZ`,
            },
          ],
        },
      ],
    };

    fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(slackPayload),
    }).catch((err) => {
      console.error("[REGISTRY WEBHOOK ERROR]", err);
    });
  }

  return NextResponse.json(
    {
      success: true,
      application_id: data.id,
      message:
        "Your certification application has been received. We'll review it and reach out within 5 business days.",
    },
    { status: 201 },
  );
}

// ---------------------------------------------------------------------------
// GET /api/registry/apply — admin listing (requires x-admin-secret header)
// ---------------------------------------------------------------------------

export async function GET(req: NextRequest) {
  const secret = process.env.REGISTRY_ADMIN_SECRET;
  if (!secret || req.headers.get("x-admin-secret") !== secret) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const db = supabaseAdmin();
  const { data, error } = await db
    .from("applications")
    .select("*")
    .order("created_at", { ascending: false })
    .limit(500);

  if (error) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }

  const rows = (data ?? []) as ApplicationRow[];
  return NextResponse.json({ count: rows.length, applications: rows });
}
