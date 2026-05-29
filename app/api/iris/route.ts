// AISeal F4 close — hardened IRIS scan-narrative endpoint.
//
// Guard order: CORS preflight → Origin/Referer lock → per-IP rate limit
// (10/hr) → global daily cap (200/day, Supabase-backed) → zod-ish validation
// → Anthropic call. Audit log to public.iris_usage on success + block.

import { NextRequest, NextResponse } from "next/server";
import Anthropic from "@anthropic-ai/sdk";
import { preflight, runGuard, logSuccess, logBlocked, withCors } from "@/lib/iris-guard";

const MAX_FINDINGS = 50;
const MODEL = "claude-sonnet-4-6";
const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

const IRIS_SYSTEM_PROMPT = `You are IRIS — Integrated Risk Insight System. You are the AI security analysis layer inside AISeal, built on Ghost99RT.

Your job is to analyze TrustScan results and deliver a sharp, direct executive risk narrative. You speak like a senior security architect — no fluff, no padding, BLUF. You understand OWASP LLM Top 10 deeply.

Rules:
- Lead with the bottom line: what is the actual risk to this organization
- Be specific about which findings matter most and why
- If the scan is clean, say so clearly and briefly
- Keep it under 150 words
- No bullet points — prose only
- Do not repeat the findings table back — interpret it
- End with one concrete recommendation
- Never say "I" — you are IRIS, write in third person or imperatively`;

export async function OPTIONS(req: NextRequest) {
  return preflight(req) ?? new Response(null, { status: 405 });
}

export async function POST(req: NextRequest) {
  const guard = await runGuard(req, "iris");
  if (!guard.ok) {
    return withCors(
      NextResponse.json({ error: guard.reason, message: guard.message }, { status: guard.status }),
      req,
    );
  }

  const t0 = Date.now();
  let promptChars = 0;
  let replyChars = 0;

  try {
    const body = await req.json();
    const { score, findings: rawFindings, model, scenario } = body;
    const findings = Array.isArray(rawFindings) ? rawFindings.slice(0, MAX_FINDINGS) : [];

    const fails = findings.filter((f: { status: string }) => f.status === "fail");
    const warns = findings.filter((f: { status: string }) => f.status === "warning");
    const flagged = [...fails, ...warns];

    const findingsSummary = flagged.length > 0
      ? flagged.map((f: { code: string; category: string; severity: string; detail: string }) =>
          `${f.code} (${f.category}) — ${f.severity.toUpperCase()}: ${f.detail}`
        ).join("\n")
      : "No findings. All checks passed.";

    const userMessage = `TrustScan Results:
TrustScore: ${score}/100
Target Model: ${model}
${scenario ? `Scenario: ${scenario}` : ""}
Fails: ${fails.length} | Warnings: ${warns.length}

Flagged Findings:
${findingsSummary}

Provide your executive risk analysis.`;
    promptChars = userMessage.length;

    const message = await client.messages.create({
      model: MODEL,
      max_tokens: 300,
      system: IRIS_SYSTEM_PROMPT,
      messages: [{ role: "user", content: userMessage }],
    });

    const narrative = message.content[0].type === "text" ? message.content[0].text : "";
    replyChars = narrative.length;

    await logSuccess({
      route: "iris",
      ip_hash: guard.ip_hash,
      origin: guard.origin,
      user_agent: guard.user_agent,
      model: MODEL,
      duration_ms: Date.now() - t0,
      prompt_chars: promptChars,
      reply_chars: replyChars,
    });

    return withCors(NextResponse.json({ narrative }), req);
  } catch (err) {
    console.error("IRIS API error:", err);
    await logBlocked({ ...guard, route: "iris", reason: "llm_error" });
    return withCors(NextResponse.json({ error: "IRIS analysis unavailable" }, { status: 500 }), req);
  }
}
