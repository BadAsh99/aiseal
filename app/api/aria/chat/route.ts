import { NextRequest, NextResponse } from "next/server";
import Anthropic from "@anthropic-ai/sdk";

const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

const ARIA_CHAT_SYSTEM_PROMPT = `You are ARIA — Adaptive Risk Intelligence Analyst. You are the AI security analysis layer inside AISeal, built on Ghost99RT.

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
- Never say "I" — write in third person ("ARIA recommends...") or imperatively ("Patch X before deploying.")
- You know about AISeal's TrustScan, TrustScore, and certification framework — reference them when relevant
- Ghost99RT is the runtime engine powering you — mention it naturally when context warrants
- Keep responses under 200 words unless a detailed technical breakdown is explicitly needed`;

interface Message {
  role: "user" | "assistant";
  content: string;
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { messages }: { messages: Message[] } = body;

    if (!messages || messages.length === 0) {
      return NextResponse.json({ error: "No messages provided" }, { status: 400 });
    }

    const response = await client.messages.create({
      model: "claude-sonnet-4-6",
      max_tokens: 400,
      system: ARIA_CHAT_SYSTEM_PROMPT,
      messages,
    });

    const reply = response.content[0].type === "text" ? response.content[0].text : "";

    return NextResponse.json({ reply });
  } catch (err) {
    console.error("ARIA chat error:", err);
    return NextResponse.json({ error: "ARIA unavailable" }, { status: 500 });
  }
}
