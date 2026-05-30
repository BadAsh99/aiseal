"use client";

// Live Endpoint Scan UI — companion to the static /scan preview.
// Submits the vendor's actual endpoint to /api/scan/live, which runs OWASP-aligned
// probes against the model and grades responses. This is the F3 close.

import { useState } from "react";
import Link from "next/link";

interface Finding {
  id: string;
  owasp: string;
  title: string;
  severity: string;
  weight: number;
  verdict: "pass" | "fail" | "partial" | "error";
  evidence: string;
  excerpt?: string;
  error?: string;
  duration_ms: number;
}

interface DualJudge {
  ran: boolean;
  judge_a?: string;
  judge_b?: string;
  agreement_count?: number;
  agreement_total?: number;
  agreement_rate?: number;
  agreement_label?: string;
}

interface LiveScanResult {
  scan_id: string;
  scan_mode: "live";
  scanned_at: string;
  endpoint_host: string;
  endpoint_type: string;
  model: string;
  trust_score: number;
  summary: { total: number; passed: number; failed: number; partial: number; errored: number };
  findings: Finding[];
  dual_judge?: DualJudge;
  signature: string;
  duration_ms: number;
  note: string;
}

const verdictStyle: Record<Finding["verdict"], { color: string; bg: string; label: string }> = {
  pass:    { color: "#00c853", bg: "rgba(0,200,83,0.08)",   label: "PASS" },
  fail:    { color: "#f85149", bg: "rgba(248,81,73,0.08)",   label: "FAIL" },
  partial: { color: "#f59e0b", bg: "rgba(245,158,11,0.08)", label: "PARTIAL" },
  error:   { color: "#6b7280", bg: "rgba(107,114,128,0.08)", label: "ERROR" },
};

function scoreColor(s: number): string {
  if (s >= 85) return "#00c853";
  if (s >= 70) return "#0080ff";
  if (s >= 50) return "#f59e0b";
  return "#f85149";
}

export default function LiveScanPage() {
  const [form, setForm] = useState({
    endpoint_url: "",
    api_key: "",
    model: "",
    endpoint_type: "openai" as "openai" | "anthropic",
    email: "",
    vendor_domain: "",
  });
  const [phase, setPhase] = useState<"form" | "running" | "done" | "error">("form");
  const [result, setResult] = useState<LiveScanResult | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setPhase("running");
    setErrorMsg(null);
    try {
      const res = await fetch("/api/scan/live", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          endpoint_url: form.endpoint_url.trim(),
          api_key: form.api_key,
          model: form.model.trim(),
          endpoint_type: form.endpoint_type,
          email: form.email.trim(),
          vendor_domain: form.vendor_domain.trim() || undefined,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setErrorMsg(
          data.message ||
            data.detail ||
            `Scan failed (${res.status}). ${data.error ?? ""}`,
        );
        setPhase("error");
        return;
      }
      setResult(data);
      setPhase("done");
    } catch (e) {
      setErrorMsg(e instanceof Error ? e.message : String(e));
      setPhase("error");
    }
  }

  return (
    <div style={{ background: "var(--bg-base)", minHeight: "100vh" }}>
      <section
        className="text-center px-6 py-16"
        style={{
          background:
            "radial-gradient(ellipse 70% 40% at 50% -5%, rgba(0,200,83,0.08) 0%, transparent 65%)",
          borderBottom: "1px solid var(--border-subtle)",
        }}
      >
        <div
          className="inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-medium mb-4"
          style={{
            background: "rgba(0,200,83,0.08)",
            border: "1px solid rgba(0,200,83,0.2)",
            color: "#00c853",
          }}
        >
          Live Endpoint Scan — Certification-eligible
        </div>
        <h1
          className="text-3xl md:text-5xl font-bold mb-4 max-w-3xl mx-auto"
          style={{ color: "var(--text-primary)", letterSpacing: "-0.025em", lineHeight: "1.1" }}
        >
          Score the model.
          <br />
          <span style={{ color: "#00c853" }}>Not the prompt.</span>
        </h1>
        <p
          className="text-base max-w-2xl mx-auto"
          style={{ color: "var(--text-secondary)", lineHeight: "1.6" }}
        >
          The static <Link href="/scan" style={{ color: "#0080ff" }}>preview scan</Link> grades a
          prompt you paste. Live Scan grades your <strong>actual model&apos;s behavior</strong> by
          sending adversarial probes to your production endpoint. Only Live Scan results are
          eligible for AISeal certification.
        </p>
      </section>

      <main className="max-w-3xl mx-auto px-6 py-10">
        {phase === "form" && (
          <form
            onSubmit={submit}
            className="rounded-2xl p-6 flex flex-col gap-4"
            style={{ background: "var(--bg-surface)", border: "1px solid var(--border-mid)" }}
          >
            <Field
              label="Endpoint URL"
              value={form.endpoint_url}
              onChange={(v) => setForm({ ...form, endpoint_url: v })}
              placeholder="https://api.your-vendor.com/v1/chat/completions"
              required
              hint="HTTPS only. Must be a public endpoint and (if you registered a vendor domain) match it."
            />
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <Field
                label="Model name"
                value={form.model}
                onChange={(v) => setForm({ ...form, model: v })}
                placeholder="gpt-4o-mini · claude-sonnet-4-6 · llama-3.1-70b"
                required
              />
              <SelectField
                label="API schema"
                value={form.endpoint_type}
                onChange={(v) => setForm({ ...form, endpoint_type: v as "openai" | "anthropic" })}
                options={[
                  { value: "openai", label: "OpenAI-compatible (default)" },
                  { value: "anthropic", label: "Anthropic /v1/messages" },
                ]}
              />
            </div>
            <Field
              label="API key"
              value={form.api_key}
              onChange={(v) => setForm({ ...form, api_key: v })}
              placeholder="sk-... — never logged, never persisted"
              required
              type="password"
              hint="Held in memory for the scan only. Not written to logs or the audit table."
            />
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <Field
                label="Email"
                type="email"
                value={form.email}
                onChange={(v) => setForm({ ...form, email: v })}
                placeholder="security@your-company.com"
                required
              />
              <Field
                label="Vendor domain (optional)"
                value={form.vendor_domain}
                onChange={(v) => setForm({ ...form, vendor_domain: v })}
                placeholder="your-vendor.com"
                hint="If set, endpoint host must match this. Stronger SSRF guard."
              />
            </div>
            <button
              type="submit"
              className="w-full text-center py-3.5 rounded-md text-sm font-semibold mt-2"
              style={{ background: "#00c853", color: "#000000", border: "none" }}
            >
              Run Live Scan →
            </button>
            <p className="text-xs" style={{ color: "var(--text-muted)" }}>
              ≈ 30–90 seconds. We send {`{N}`} adversarial probes to your endpoint and grade the
              responses. Rate-limited (5 / IP / hour).
            </p>
          </form>
        )}

        {phase === "running" && (
          <div
            className="rounded-2xl p-12 text-center flex flex-col items-center gap-4"
            style={{ background: "var(--bg-surface)", border: "1px solid var(--border-mid)" }}
          >
            <div
              className="w-12 h-12 border-4 rounded-full animate-spin"
              style={{ borderColor: "var(--border-mid)", borderTopColor: "#00c853" }}
            />
            <p className="font-medium" style={{ color: "var(--text-primary)" }}>
              Running adversarial probes against {new URL(form.endpoint_url).hostname}…
            </p>
            <p className="text-sm" style={{ color: "var(--text-muted)" }}>
              Up to 90 seconds. Don&apos;t refresh.
            </p>
          </div>
        )}

        {phase === "error" && (
          <div
            className="rounded-2xl p-8 text-center"
            style={{ background: "var(--bg-surface)", border: "1px solid rgba(248,81,73,0.3)" }}
          >
            <p className="font-semibold mb-2" style={{ color: "#f85149" }}>
              Scan could not complete
            </p>
            <p className="text-sm mb-4" style={{ color: "var(--text-muted)" }}>
              {errorMsg}
            </p>
            <button
              onClick={() => setPhase("form")}
              className="px-4 py-2 rounded-md text-sm font-semibold"
              style={{
                background: "transparent",
                color: "var(--text-primary)",
                border: "1px solid var(--border-mid)",
              }}
            >
              ← Try again
            </button>
          </div>
        )}

        {phase === "done" && result && (
          <div className="flex flex-col gap-6">
            {/* Score card */}
            <div
              className="rounded-2xl p-8 text-center"
              style={{ background: "var(--bg-surface)", border: "1px solid var(--border-mid)" }}
            >
              <p
                className="text-xs font-semibold uppercase tracking-widest mb-2"
                style={{ color: "var(--text-muted)" }}
              >
                Live TrustScore
              </p>
              <div
                className="font-black tabular-nums"
                style={{ color: scoreColor(result.trust_score), fontSize: 72, lineHeight: 1 }}
              >
                {result.trust_score}
                <span className="text-2xl" style={{ color: "var(--text-muted)" }}>
                  /100
                </span>
              </div>
              <div className="flex items-center justify-center gap-4 mt-4 text-xs" style={{ color: "var(--text-muted)" }}>
                <span>{result.summary.passed} passed</span>
                <span>·</span>
                <span style={{ color: result.summary.failed > 0 ? "#f85149" : undefined }}>
                  {result.summary.failed} failed
                </span>
                <span>·</span>
                <span>{result.summary.partial} partial</span>
                {result.summary.errored > 0 && (
                  <>
                    <span>·</span>
                    <span>{result.summary.errored} errored</span>
                  </>
                )}
              </div>
              <p className="text-xs mt-3" style={{ color: "var(--text-muted)" }}>
                {result.endpoint_host} · {result.model} · {Math.round(result.duration_ms / 1000)}s
              </p>
              {result.dual_judge?.ran && (
                <div
                  className="mt-4 rounded-xl px-4 py-3 text-center"
                  style={{ background: "rgba(0,200,83,0.08)", border: "1px solid rgba(0,200,83,0.25)" }}
                >
                  <p className="text-xs font-black uppercase tracking-widest mb-1" style={{ color: "#00c853" }}>
                    Dual-Judge Agreement
                  </p>
                  <p className="text-2xl font-black" style={{ color: "#00c853" }}>
                    {result.dual_judge.agreement_label}
                  </p>
                  <div className="flex justify-center gap-1 mt-2">
                    {Array.from({ length: result.dual_judge.agreement_total ?? 0 }).map((_, i) => (
                      <span
                        key={i}
                        className="inline-block w-5 h-5 rounded"
                        style={{
                          background: i < (result.dual_judge?.agreement_count ?? 0) ? "#00c853" : "#f85149",
                        }}
                      />
                    ))}
                  </div>
                  <p className="text-xs mt-2" style={{ color: "var(--text-muted)" }}>
                    Judge A: rule-based grader · Judge B: {result.dual_judge.judge_b}
                  </p>
                </div>
              )}
              <p className="text-xs mt-3 font-mono break-all" style={{ color: "var(--text-subtle)" }}>
                sig {result.signature}
              </p>
            </div>

            {/* Findings */}
            <div className="flex flex-col gap-3">
              <p
                className="text-xs font-semibold uppercase tracking-widest"
                style={{ color: "var(--text-muted)" }}
              >
                Per-probe findings ({result.findings.length})
              </p>
              {result.findings.map((f) => {
                const v = verdictStyle[f.verdict];
                return (
                  <div
                    key={f.id}
                    className="rounded-xl p-5"
                    style={{
                      background: "var(--bg-surface)",
                      border: `1px solid ${v.color}30`,
                    }}
                  >
                    <div className="flex flex-wrap items-center gap-2 mb-2">
                      <span
                        className="text-xs font-bold px-2 py-0.5 rounded-md"
                        style={{
                          background: v.bg,
                          color: v.color,
                          border: `1px solid ${v.color}40`,
                        }}
                      >
                        {v.label}
                      </span>
                      <span
                        className="text-xs font-mono"
                        style={{ color: "var(--text-muted)" }}
                      >
                        {f.owasp}
                      </span>
                      <span className="text-sm font-semibold" style={{ color: "var(--text-primary)" }}>
                        {f.title}
                      </span>
                      <span className="text-xs ml-auto" style={{ color: "var(--text-subtle)" }}>
                        weight {f.weight} · {f.duration_ms}ms
                      </span>
                    </div>
                    <p className="text-sm mb-2" style={{ color: "var(--text-secondary)" }}>
                      {f.evidence}
                    </p>
                    {f.excerpt && (
                      <pre
                        className="text-xs font-mono p-3 rounded-md overflow-x-auto whitespace-pre-wrap"
                        style={{
                          background: "var(--bg-elevated, #0a0a0a)",
                          color: "#9ca3af",
                          border: "1px solid var(--border-subtle)",
                          margin: 0,
                        }}
                      >
                        {f.excerpt}
                      </pre>
                    )}
                  </div>
                );
              })}
            </div>

            <div className="flex flex-wrap gap-3 mt-2">
              <Link
                href="/registry/apply"
                className="inline-flex items-center gap-2 px-5 py-2.5 rounded-md text-sm font-semibold"
                style={{ background: "#00c853", color: "#000000", textDecoration: "none" }}
              >
                Apply for Certification with this score →
              </Link>
              <button
                onClick={() => {
                  setResult(null);
                  setPhase("form");
                }}
                className="px-5 py-2.5 rounded-md text-sm font-semibold"
                style={{
                  background: "transparent",
                  color: "var(--text-muted)",
                  border: "1px solid var(--border-mid)",
                }}
              >
                Run another scan
              </button>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}

function Field({
  label,
  value,
  onChange,
  placeholder,
  type = "text",
  required,
  hint,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  type?: string;
  required?: boolean;
  hint?: string;
}) {
  return (
    <div>
      <label
        className="block text-sm font-semibold mb-1.5"
        style={{ color: "var(--text-primary)" }}
      >
        {label}
      </label>
      <input
        type={type}
        required={required}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="w-full px-4 py-2.5 rounded-lg outline-none text-sm"
        style={{
          background: "var(--bg-elevated, #0a0a0a)",
          color: "var(--text-primary)",
          border: "1px solid var(--border-mid)",
        }}
      />
      {hint && (
        <p className="text-xs mt-1" style={{ color: "var(--text-muted)" }}>
          {hint}
        </p>
      )}
    </div>
  );
}

function SelectField({
  label,
  value,
  onChange,
  options,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  options: Array<{ value: string; label: string }>;
}) {
  return (
    <div>
      <label
        className="block text-sm font-semibold mb-1.5"
        style={{ color: "var(--text-primary)" }}
      >
        {label}
      </label>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="w-full px-4 py-2.5 rounded-lg outline-none text-sm"
        style={{
          background: "var(--bg-elevated, #0a0a0a)",
          color: "var(--text-primary)",
          border: "1px solid var(--border-mid)",
        }}
      >
        {options.map((opt) => (
          <option key={opt.value} value={opt.value}>
            {opt.label}
          </option>
        ))}
      </select>
    </div>
  );
}
