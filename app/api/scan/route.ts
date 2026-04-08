import { NextRequest, NextResponse } from "next/server";

const SCANNER_URL = process.env.SCANNER_API_URL ?? "http://localhost:8000";
const SCANNER_KEY = process.env.SCANNER_API_KEY ?? "";

export async function POST(req: NextRequest) {
  let body: { prompt?: string; model?: string; scenario?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const prompt = (body.prompt || "").trim();
  if (!prompt) {
    return NextResponse.json({ error: "prompt is required" }, { status: 400 });
  }

  try {
    const res = await fetch(`${SCANNER_URL}/v1/scan`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-AISeal-Key": SCANNER_KEY,
      },
      body: JSON.stringify({
        prompt,
        model: body.model ?? "claude-sonnet-4-6",
        scenario: body.scenario ?? null,
      }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      return NextResponse.json(
        { error: err.detail ?? "Scanner service error" },
        { status: res.status }
      );
    }

    const data = await res.json();
    return NextResponse.json(data);
  } catch {
    return NextResponse.json({ error: "Scanner service unreachable" }, { status: 503 });
  }
}
