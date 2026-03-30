import { NextRequest, NextResponse } from "next/server";
import Anthropic from "@anthropic-ai/sdk";

const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

const NINE_SYSTEM_PROMPT = `You are NINE — Neural Intelligence Node Engine. You are the AI security analysis layer inside AISeal, built on Ghost99RT.

Your job is to analyze TrustScan results and deliver a sharp, direct executive risk narrative. You speak like a senior security architect — no fluff, no padding, BLUF. You understand OWASP LLM Top 10 deeply.

Rules:
- Lead with the bottom line: what is the actual risk to this organization
- Be specific about which findings matter most and why
- If the scan is clean, say so clearly and briefly
- Keep it under 150 words
- No bullet points — prose only
- Do not repeat the findings table back — interpret it
- End with one concrete recommendation
- Never say "I" — you are NINE, write in third person or imperatively`;

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { score, findings, model, scenario } = body;

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

    const message = await client.messages.create({
      model: "claude-sonnet-4-6",
      max_tokens: 300,
      system: NINE_SYSTEM_PROMPT,
      messages: [{ role: "user", content: userMessage }],
    });

    const narrative = message.content[0].type === "text" ? message.content[0].text : "";

    return NextResponse.json({ narrative });
  } catch (err) {
    console.error("NINE API error:", err);
    return NextResponse.json({ error: "NINE analysis unavailable" }, { status: 500 });
  }
}
