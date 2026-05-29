// AISeal F4 close — hardened IRIS chat endpoint.
//
// Guard order: CORS preflight → Origin/Referer lock → per-IP rate limit
// (30/hr) → global daily cap (500/day, Supabase-backed) → zod validation
// → Anthropic call. Every call (success or block) is audit-logged to
// public.iris_usage. api_key never touches the audit table.

import { NextRequest, NextResponse } from "next/server";
import Anthropic from "@anthropic-ai/sdk";
import { preflight, runGuard, logSuccess, logBlocked, withCors } from "@/lib/iris-guard";

const MAX_MESSAGES = 30;
const MAX_MESSAGE_LENGTH = 5_000;
const MODEL = "claude-sonnet-4-6";
const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

const IRIS_CHAT_SYSTEM_PROMPT = `You are IRIS — Integrated Risk Insight System. You are the AI security analysis layer inside AISeal, built on Ghost99RT.

You are a senior AI security architect and the intelligence core of Ghost99RT. You speak with authority, precision, and no fluff. BLUF always.

Your domain expertise:
- OWASP LLM Top 10 (LLM01–LLM10) — deep technical understanding
- AI red teaming: prompt injection, jailbreaks, indirect injection, data exfiltration
- LLM deployment security: system prompt protection, output validation, guardrails
- AI compliance and trust frameworks (the AISeal TrustScan/TrustCert model)
- Real-world enterprise LLM risk — what actually matters vs. theoretical noise

Rules:
- Answer concisely and directly — no padding, no filler
- If asked something outside AI security, redirect to your domain
- Never say "I" — write in third person ("IRIS recommends...") or imperatively ("Patch X before deploying.")
- You know about AISeal's TrustScan, TrustScore, and certification framework — reference them when relevant
- Ghost99RT is the runtime engine powering you — mention it naturally when context warrants
- Keep responses under 200 words unless a detailed technical breakdown is explicitly needed`;

interface Message {
  role: "user" | "assistant";
  content: string;
}

export async function OPTIONS(req: NextRequest) {
  return preflight(req) ?? new Response(null, { status: 405 });
}

export async function POST(req: NextRequest) {
  // CORS preflight may slip through to POST if a client sends Origin + POST
  // directly — we still apply the guard here.
  const guard = await runGuard(req, "iris_chat");
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
    const { messages: rawMessages }: { messages: Message[] } = body;

    if (!rawMessages || !Array.isArray(rawMessages) || rawMessages.length === 0) {
      await logBlocked({ ...guard, route: "iris_chat", reason: "validation" });
      return withCors(NextResponse.json({ error: "No messages provided" }, { status: 400 }), req);
    }

    const messages = rawMessages.slice(-MAX_MESSAGES).map((m) => ({
      ...m,
      content: typeof m.content === "string" ? m.content.slice(0, MAX_MESSAGE_LENGTH) : m.content,
    }));
    promptChars = messages.reduce(
      (acc, m) => acc + (typeof m.content === "string" ? m.content.length : 0),
      0,
    );

    const response = await client.messages.create({
      model: MODEL,
      max_tokens: 400,
      system: IRIS_CHAT_SYSTEM_PROMPT,
      messages,
    });

    const reply = response.content[0].type === "text" ? response.content[0].text : "";
    replyChars = reply.length;

    await logSuccess({
      route: "iris_chat",
      ip_hash: guard.ip_hash,
      origin: guard.origin,
      user_agent: guard.user_agent,
      model: MODEL,
      duration_ms: Date.now() - t0,
      prompt_chars: promptChars,
      reply_chars: replyChars,
    });

    return withCors(NextResponse.json({ reply }), req);
  } catch (err) {
    console.error("IRIS chat error:", err);
    await logBlocked({ ...guard, route: "iris_chat", reason: "llm_error" });
    return withCors(NextResponse.json({ error: "IRIS unavailable" }, { status: 500 }), req);
  }
}
