// Outbound LLM API client for /api/scan/live.
//
// Supports OpenAI-compatible /v1/chat/completions endpoints (de facto standard
// — works for OpenAI, Anthropic via their SDK, Together, Anyscale, vLLM-deployed
// models, Groq, OpenRouter, etc.) and Anthropic's native /v1/messages schema.
//
// Each call is hard-timeouted, and the maximum response payload size is capped
// to keep memory bounded (a malicious endpoint can't blow us up by streaming
// gigabytes of garbage).

export type EndpointType = "openai" | "anthropic";

export interface CallParams {
  endpoint_url: string;
  api_key: string;
  model: string;
  endpoint_type: EndpointType;
  prompt: string;
  max_tokens?: number;
  timeout_ms?: number;
}

export interface CallResult {
  ok: boolean;
  text: string;
  status: number;
  duration_ms: number;
  error?: string;
}

// 1 MB cap on the response body to prevent memory amplification.
const MAX_RESPONSE_BYTES = 1_000_000;

async function readBodyCapped(res: Response): Promise<string> {
  const reader = res.body?.getReader();
  if (!reader) return await res.text();
  const decoder = new TextDecoder();
  let total = 0;
  let out = "";
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_RESPONSE_BYTES) {
      try { await reader.cancel(); } catch { /* ignore */ }
      throw new Error("response_too_large");
    }
    out += decoder.decode(value, { stream: true });
  }
  out += decoder.decode();
  return out;
}

export async function callLlm(params: CallParams): Promise<CallResult> {
  const timeout_ms = params.timeout_ms ?? 15_000;
  const max_tokens = params.max_tokens ?? 400;

  const controller = new AbortController();
  const t0 = Date.now();
  const timer = setTimeout(() => controller.abort(), timeout_ms);

  try {
    let body: Record<string, unknown>;
    let headers: Record<string, string>;

    if (params.endpoint_type === "anthropic") {
      headers = {
        "content-type": "application/json",
        "x-api-key": params.api_key,
        "anthropic-version": "2023-06-01",
      };
      body = {
        model: params.model,
        max_tokens,
        messages: [{ role: "user", content: params.prompt }],
      };
    } else {
      // OpenAI-compatible
      headers = {
        "content-type": "application/json",
        authorization: `Bearer ${params.api_key}`,
      };
      body = {
        model: params.model,
        max_tokens,
        messages: [{ role: "user", content: params.prompt }],
        temperature: 0,                   // deterministic-ish for grading
      };
    }

    const res = await fetch(params.endpoint_url, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
      signal: controller.signal,
      // Don't follow cross-origin redirects — could redirect to internal hosts.
      redirect: "error",
    });

    const raw = await readBodyCapped(res);
    if (!res.ok) {
      return {
        ok: false,
        text: "",
        status: res.status,
        duration_ms: Date.now() - t0,
        error: `HTTP ${res.status}: ${raw.slice(0, 300)}`,
      };
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      return { ok: false, text: "", status: res.status, duration_ms: Date.now() - t0, error: "non_json_response" };
    }

    const text = extractText(parsed, params.endpoint_type);
    return {
      ok: true,
      text,
      status: res.status,
      duration_ms: Date.now() - t0,
    };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    const aborted = msg.includes("abort") || msg.includes("AbortError");
    return {
      ok: false,
      text: "",
      status: 0,
      duration_ms: Date.now() - t0,
      error: aborted ? `timeout after ${timeout_ms}ms` : msg,
    };
  } finally {
    clearTimeout(timer);
  }
}

function extractText(payload: unknown, endpoint_type: EndpointType): string {
  if (typeof payload !== "object" || payload === null) return "";

  if (endpoint_type === "anthropic") {
    // { content: [{ type: "text", text: "..." }, ...] }
    const content = (payload as { content?: Array<{ type?: string; text?: string }> }).content;
    if (Array.isArray(content)) {
      return content
        .filter((c) => c?.type === "text" && typeof c?.text === "string")
        .map((c) => c.text as string)
        .join("\n");
    }
    return "";
  }

  // OpenAI-compatible: { choices: [{ message: { content: "..." } }] }
  const choices = (payload as { choices?: Array<{ message?: { content?: string }; text?: string }> }).choices;
  if (Array.isArray(choices) && choices.length > 0) {
    const c = choices[0];
    if (typeof c.message?.content === "string") return c.message.content;
    if (typeof c.text === "string") return c.text;
  }
  return "";
}
