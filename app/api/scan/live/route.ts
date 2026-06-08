// AISeal F3 — live endpoint scan.
//
// POST /api/scan/live
//   { endpoint_url, api_key, model, endpoint_type, email, vendor_domain? }
//
// Runs the adversarial probes in lib/scan-probes.ts against the vendor's actual
// LLM endpoint, grades the responses, computes a TrustScore based on observed
// behavior. This is what binds the score to the live model and closes F3.
//
// Hard guards:
//   - SSRF: HTTPS only, public-IP host, blocklisted hostnames, vendor_domain
//     enforced if provided.
//   - Three abuse gates same as /api/audit: zod + per-IP rate limit + daily cap.
//   - Per-probe timeout 15s, max-response-body 1MB, concurrency 2.
//   - api_key is NEVER persisted or logged. Lives in memory for the scan only.

import { NextResponse } from "next/server";
import { createHash } from "node:crypto";
import { z } from "zod";
import { rateLimit } from "@/app/lib/rate-limit";
import { supabaseAdmin } from "../../../../lib/supabase/server";
import { checkUrl } from "../../../../lib/scan-ssrf";
import {
  PROBES,
  TOTAL_PROBE_WEIGHT,
  OWASP_CATEGORIES,
  MULTITURN_PROBE_COUNT,
  type Verdict,
} from "../../../../lib/scan-probes";
import { callLlm, type EndpointType } from "../../../../lib/scan-client";
import { signBadge } from "../../../../lib/badge-hmac";
import { runDualJudge } from "../../../../lib/scan-judge";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";
export const maxDuration = 120;

const DAILY_CAP = 100;
const CONCURRENCY = 2;

const LiveScanSchema = z.object({
  endpoint_url: z.string().url().max(500),
  api_key: z.string().min(8).max(500),
  model: z.string().min(1).max(120),
  endpoint_type: z.enum(["openai", "anthropic"]),
  email: z.string().email().max(200),
  vendor_domain: z.string().max(200).optional(),
});

function ipFromHeaders(req: Request): string {
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

interface ProbeFinding {
  id: string;
  owasp: string;
  title: string;
  severity: string;
  weight: number;
  verdict: Verdict | "error";
  evidence: string;
  excerpt?: string;
  error?: string;
  duration_ms: number;
}

/** Convert verdicts to a 0-100 TrustScore using probe weights. */
function computeScore(findings: ProbeFinding[]): number {
  let earned = 0;
  let possible = 0;
  for (const f of findings) {
    possible += f.weight;
    if (f.verdict === "pass") earned += f.weight;
    else if (f.verdict === "partial") earned += f.weight * 0.5;
    else if (f.verdict === "error") earned += f.weight * 0.5; // can't penalize for our errors
    // fail = 0
  }
  if (possible === 0) return 0;
  return Math.round((earned / possible) * 100);
}

/** Run probes with bounded concurrency. */
async function runProbes(
  endpoint_url: string,
  api_key: string,
  model: string,
  endpoint_type: EndpointType,
): Promise<ProbeFinding[]> {
  const findings: ProbeFinding[] = new Array(PROBES.length);
  let idx = 0;

  async function worker() {
    while (true) {
      const i = idx++;
      if (i >= PROBES.length) return;
      const probe = PROBES[i];
      const t0 = Date.now();
      // Multi-turn probes carry a `messages` conversation; single-shot probes
      // carry a `prompt`. Pass whichever is present — callLlm normalizes both.
      const call = await callLlm({
        endpoint_url,
        api_key,
        model,
        endpoint_type,
        prompt: probe.prompt,
        messages: probe.messages,
        max_tokens: 400,
        timeout_ms: 15_000,
      });
      const duration = Date.now() - t0;
      if (!call.ok) {
        findings[i] = {
          id: probe.id,
          owasp: probe.owasp,
          title: probe.title,
          severity: probe.severity,
          weight: probe.weight,
          verdict: "error",
          evidence: `Probe could not complete: ${call.error ?? "unknown error"}`,
          error: call.error,
          duration_ms: duration,
        };
        continue;
      }
      const graded = probe.grade(call.text);
      findings[i] = {
        id: probe.id,
        owasp: probe.owasp,
        title: probe.title,
        severity: probe.severity,
        weight: probe.weight,
        verdict: graded.verdict,
        evidence: graded.evidence,
        excerpt: graded.excerpt,
        duration_ms: duration,
      };
    }
  }

  await Promise.all(Array.from({ length: CONCURRENCY }, () => worker()));
  return findings;
}

export async function POST(req: Request) {
  const t0 = Date.now();
  const ip = ipFromHeaders(req);
  const { ok: rlOk } = rateLimit(`live-scan:${ip}`, { maxRequests: 5, windowMs: 60 * 60 * 1000 });
  if (!rlOk) {
    return NextResponse.json(
      { error: "rate_limited", message: "Too many scans from your IP. Try again in an hour." },
      { status: 429 },
    );
  }

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "invalid_json" }, { status: 400 });
  }
  const parsed = LiveScanSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json(
      { error: "validation", details: parsed.error.flatten() },
      { status: 400 },
    );
  }
  const { endpoint_url, api_key, model, endpoint_type, email, vendor_domain } = parsed.data;

  // Global daily cap (hard ceiling regardless of IP)
  const admin = supabaseAdmin();
  const dayStart = new Date();
  dayStart.setHours(0, 0, 0, 0);
  const { count } = await admin
    .from("live_scans")
    .select("*", { count: "exact", head: true })
    .gte("created_at", dayStart.toISOString());
  if ((count ?? 0) >= DAILY_CAP) {
    return NextResponse.json(
      { error: "daily_cap", message: "Live scan daily capacity reached. Try again tomorrow." },
      { status: 429 },
    );
  }

  // SSRF guard
  const ssrf = checkUrl(endpoint_url, vendor_domain ?? null);
  if (!ssrf.ok) {
    // Audit-log the rejected attempt — these are the high-signal abuse events.
    try {
      await admin.from("live_scans").insert({
        email,
        ip_hash: hashIp(ip),
        user_agent: req.headers.get("user-agent")?.slice(0, 300) ?? null,
        endpoint_host: ssrf.host ?? "unknown",
        endpoint_type,
        model,
        vendor_domain: vendor_domain ?? null,
        trust_score: 0,
        probes_total: 0,
        findings: [],
        duration_ms: Date.now() - t0,
        ssrf_check: ssrf.reason,
        errored: true,
        error_message: `SSRF guard rejected: ${ssrf.detail ?? ssrf.reason}`,
      });
    } catch { /* logging must never break the response */ }

    return NextResponse.json(
      {
        error: "ssrf_rejected",
        reason: ssrf.reason,
        detail: ssrf.detail,
        message:
          "The endpoint URL did not pass safety checks. Endpoint must be HTTPS, public, " +
          "and (if a vendor domain is registered) match that domain.",
      },
      { status: 400 },
    );
  }

  // Run probes
  let findings: ProbeFinding[];
  try {
    findings = await runProbes(endpoint_url, api_key, model, endpoint_type);
  } catch (e) {
    return NextResponse.json(
      { error: "scan_failed", message: e instanceof Error ? e.message : String(e) },
      { status: 500 },
    );
  }

  const score = computeScore(findings);
  const passed = findings.filter((f) => f.verdict === "pass").length;
  const failed = findings.filter((f) => f.verdict === "fail").length;
  const partial = findings.filter((f) => f.verdict === "partial").length;
  const errored = findings.filter((f) => f.verdict === "error").length;
  const scan_id = crypto.randomUUID();
  const scanned_at = new Date().toISOString();

  // Judge B — run in parallel with signing, doesn't block the response if it fails.
  // Look the probe prompt up BY ID (not by post-filter index — filtering out error
  // findings shifts indices, and multi-turn probes have no single `prompt`; we
  // render their conversation for the judge's context instead).
  const probeById = new Map(PROBES.map((p) => [p.id, p]));
  const renderProbePrompt = (id: string): string => {
    const p = probeById.get(id);
    if (!p) return "";
    if (p.messages && p.messages.length > 0) {
      return p.messages.map((m) => `${m.role.toUpperCase()}: ${m.content}`).join("\n");
    }
    return p.prompt ?? "";
  };
  const dualJudgePromise = runDualJudge(
    findings
      .filter((f) => f.verdict !== "error")
      .map((f) => ({
        id: f.id,
        owasp: f.owasp,
        title: f.title,
        prompt: renderProbePrompt(f.id),
        judge_a_verdict: f.verdict as Verdict,
        response_text: f.excerpt ?? f.evidence,
      }))
  ).catch(() => null);

  const signature = signBadge({
    cert_id: scan_id,
    vendor_domain: vendor_domain ?? null,
    score,
    issued_date: scanned_at.slice(0, 10),
  });

  const dualJudge = await dualJudgePromise;
  const duration_ms = Date.now() - t0;

  // Audit log — NO api_key, NO full responses, just the verdicts + evidence
  try {
    await admin.from("live_scans").insert({
      id: scan_id,
      email,
      ip_hash: hashIp(ip),
      user_agent: req.headers.get("user-agent")?.slice(0, 300) ?? null,
      endpoint_host: ssrf.host,
      endpoint_type,
      model,
      vendor_domain: vendor_domain ?? null,
      trust_score: score,
      probes_total: findings.length,
      probes_passed: passed,
      probes_failed: failed,
      probes_partial: partial,
      probes_errored: errored,
      findings: findings.map((f) => ({
        id: f.id,
        owasp: f.owasp,
        title: f.title,
        severity: f.severity,
        weight: f.weight,
        verdict: f.verdict,
        evidence: f.evidence,
        excerpt: f.excerpt,
        duration_ms: f.duration_ms,
      })),
      duration_ms,
      ssrf_check: ssrf.reason,
      errored: false,
      dual_judge_ran: dualJudge?.ran ?? false,
      judge_b_verdicts: dualJudge?.judge_b_verdicts ?? null,
      judge_agreement_count: dualJudge?.judge_agreement_count ?? null,
      judge_agreement_rate: dualJudge?.judge_agreement_rate ?? null,
      judge_b_model: dualJudge?.judge_b_model ?? null,
      judge_b_unavailable_count: dualJudge?.judge_b_unavailable_count ?? null,
      judge_confidence: dualJudge?.confidence ?? null,
      judge_same_lineage: dualJudge?.same_lineage ?? null,
      grader_version: "v0.3.2",
    });
  } catch (e) {
    console.error("[scan/live] audit log insert failed", e);
  }

  return NextResponse.json({
    scan_id,
    scan_mode: "live",
    scanned_at,
    endpoint_host: ssrf.host,
    endpoint_type,
    model,
    trust_score: score,
    total_probe_weight: TOTAL_PROBE_WEIGHT,
    dual_judge: dualJudge?.ran ? {
      ran: true,
      judge_a: "deterministic-grader-v0.3.2",
      judge_b: dualJudge.judge_b_model,
      // Agreement is counted ONLY over probes where Judge B was available, so the
      // denominator reflects real dual-confirmations — not faked ones.
      agreement_count: dualJudge.judge_agreement_count,
      agreement_total:
        findings.filter((f) => f.verdict !== "error").length - dualJudge.judge_b_unavailable_count,
      agreement_rate: dualJudge.judge_agreement_rate,
      agreement_label: `${dualJudge.judge_agreement_count}/${
        findings.filter((f) => f.verdict !== "error").length - dualJudge.judge_b_unavailable_count
      } dual-confirmed judges agree`,
      judge_b_unavailable_count: dualJudge.judge_b_unavailable_count,
      confidence: dualJudge.confidence,
      same_lineage: dualJudge.same_lineage,
      lineage_note: dualJudge.lineage_note,
      verdicts: dualJudge.judge_b_verdicts,
    } : { ran: false },
    summary: {
      total: findings.length,
      passed,
      failed,
      partial,
      errored,
    },
    // Scope-state the score: what was actually measured, so the number is never
    // read as a comprehensive guarantee.
    coverage: {
      probes_total: findings.length,
      single_shot: findings.length - MULTITURN_PROBE_COUNT,
      multi_turn: MULTITURN_PROBE_COUNT,
      owasp_categories: OWASP_CATEGORIES,
      owasp_category_count: OWASP_CATEGORIES.length,
      note:
        `${findings.length - MULTITURN_PROBE_COUNT} single-shot + ${MULTITURN_PROBE_COUNT} multi-turn ` +
        `probes across OWASP ${OWASP_CATEGORIES[0]}–${OWASP_CATEGORIES[OWASP_CATEGORIES.length - 1]}. ` +
        "Score is scope-bounded to these probes — it is a behavioral signal, not a guarantee of safety.",
    },
    findings,
    signature,
    duration_ms,
    note:
      "This score reflects observed behavior of the live endpoint, not pattern matching on a static prompt. " +
      "Only Live Scan results are eligible for AISeal certification.",
  });
}
