"use client";

import { useState } from "react";

interface QRFinding {
  check: string;
  status: "vulnerable" | "warning" | "quantum-safe" | "unknown";
  severity: "critical" | "high" | "medium" | "low" | "info";
  detail: string;
  current_value: string;
  recommendation: string;
}

interface QRScanResult {
  scan_id: string;
  target: string;
  hostname: string;
  qs_score: number;
  hndl_risk: "critical" | "high" | "medium" | "low";
  findings: QRFinding[];
  tls_connected: boolean;
  tls_version: string;
  cipher_suite: string;
  key_exchange: string;
  cert_sig_alg: string;
  cert_subject_cn: string;
  cert_valid_to: string;
  scan_duration_ms: number;
  timestamp: string;
  recommendation_summary: string[];
  nist_pqc_refs: string[];
}

type PageState = "idle" | "scanning" | "result" | "error";

const STATUS_COLORS: Record<QRFinding["status"], string> = {
  vulnerable: "#ff4444",
  warning: "#f59e0b",
  "quantum-safe": "#00c853",
  unknown: "#666",
};

const STATUS_LABELS: Record<QRFinding["status"], string> = {
  vulnerable: "VULNERABLE",
  warning: "WARNING",
  "quantum-safe": "QS",
  unknown: "UNKNOWN",
};

const HNDL_COLORS: Record<QRScanResult["hndl_risk"], string> = {
  critical: "#ff4444",
  high: "#f97316",
  medium: "#f59e0b",
  low: "#00c853",
};

function ScoreGauge({ score }: { score: number }) {
  const color = score >= 80 ? "#00c853" : score >= 50 ? "#f59e0b" : "#ff4444";
  const label = score >= 80 ? "QS Ready" : score >= 50 ? "Partial" : "Vulnerable";
  return (
    <div style={{ textAlign: "center", padding: "2rem 0" }}>
      <div style={{ fontSize: "4rem", fontWeight: 700, color, fontFamily: "monospace", lineHeight: 1 }}>
        {score}
      </div>
      <div style={{ fontSize: "0.75rem", color: "#888", textTransform: "uppercase", letterSpacing: "0.1em", marginTop: "0.25rem" }}>
        Quantum Score
      </div>
      <div style={{
        display: "inline-block", marginTop: "0.5rem", padding: "0.25rem 0.75rem",
        borderRadius: "4px", background: color + "22", color, fontSize: "0.75rem",
        fontWeight: 600, letterSpacing: "0.08em",
      }}>
        {label}
      </div>
    </div>
  );
}

function FindingCard({ finding }: { finding: QRFinding }) {
  const [open, setOpen] = useState(false);
  const color = STATUS_COLORS[finding.status];
  return (
    <div
      style={{
        borderLeft: `3px solid ${color}`,
        padding: "0.75rem 1rem",
        marginBottom: "0.5rem",
        background: "#111",
        borderRadius: "0 4px 4px 0",
        cursor: "pointer",
      }}
      onClick={() => setOpen(!open)}
    >
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <span style={{ fontWeight: 600, fontSize: "0.9rem" }}>{finding.check}</span>
        <div style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
          <span style={{
            fontSize: "0.65rem", fontWeight: 700, letterSpacing: "0.1em",
            color, background: color + "22", padding: "0.1rem 0.4rem", borderRadius: "3px",
          }}>
            {STATUS_LABELS[finding.status]}
          </span>
          <span style={{ color: "#444", fontSize: "0.75rem" }}>{open ? "▲" : "▼"}</span>
        </div>
      </div>
      {open && (
        <div style={{ marginTop: "0.75rem", fontSize: "0.82rem", lineHeight: 1.6 }}>
          <div style={{ color: "#ccc", marginBottom: "0.5rem" }}>{finding.detail}</div>
          <div style={{ color: "#888", marginBottom: "0.25rem" }}>
            <span style={{ color: "#555" }}>Current: </span>
            <code style={{ color: "#f59e0b", fontSize: "0.8rem" }}>{finding.current_value}</code>
          </div>
          <div style={{ color: "#888" }}>
            <span style={{ color: "#555" }}>Rec: </span>
            <span style={{ color: "#0080ff" }}>{finding.recommendation}</span>
          </div>
        </div>
      )}
    </div>
  );
}

export default function QuantumScanPage() {
  const [target, setTarget] = useState("");
  const [state, setState] = useState<PageState>("idle");
  const [result, setResult] = useState<QRScanResult | null>(null);
  const [errorMsg, setErrorMsg] = useState("");

  async function runScan() {
    if (!target.trim()) return;
    setState("scanning");
    setErrorMsg("");
    try {
      const res = await fetch("/api/scan/quantum", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: target.trim() }),
      });
      const data = await res.json();
      if (!res.ok) {
        setErrorMsg(data.error ?? "Scan failed");
        setState("error");
        return;
      }
      setResult(data);
      setState("result");
    } catch {
      setErrorMsg("Network error — could not reach scan API");
      setState("error");
    }
  }

  return (
    <div style={{ maxWidth: "760px", margin: "0 auto", padding: "2rem 1.5rem", fontFamily: "monospace" }}>
      {/* Header */}
      <div style={{ marginBottom: "2rem" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", marginBottom: "0.5rem" }}>
          <div style={{
            background: "#0080ff22", border: "1px solid #0080ff44",
            borderRadius: "4px", padding: "0.25rem 0.6rem",
            fontSize: "0.7rem", color: "#0080ff", fontWeight: 700, letterSpacing: "0.1em",
          }}>
            BETA
          </div>
          <span style={{ fontSize: "0.75rem", color: "#555" }}>NIST FIPS 203/204/205 Compliance Check</span>
        </div>
        <h1 style={{ fontSize: "1.5rem", fontWeight: 700, margin: 0, color: "#fff" }}>
          Quantum Readiness Scan
        </h1>
        <p style={{ color: "#888", marginTop: "0.5rem", fontSize: "0.85rem", lineHeight: 1.6 }}>
          Probe an AI vendor endpoint for post-quantum cryptography readiness.
          Checks TLS key exchange, certificate signing algorithm, and Harvest Now Decrypt Later (HNDL) exposure.
        </p>
      </div>

      {/* Scan input */}
      <div style={{ marginBottom: "1.5rem" }}>
        <div style={{ display: "flex", gap: "0.5rem" }}>
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && runScan()}
            placeholder="api.youraisystem.com or https://..."
            disabled={state === "scanning"}
            style={{
              flex: 1, padding: "0.6rem 0.9rem",
              background: "#111", border: "1px solid #333", borderRadius: "4px",
              color: "#e5e7eb", fontSize: "0.85rem", outline: "none",
              fontFamily: "monospace",
            }}
          />
          <button
            onClick={runScan}
            disabled={state === "scanning" || !target.trim()}
            style={{
              padding: "0.6rem 1.25rem",
              background: state === "scanning" ? "#333" : "#0080ff",
              color: "#fff", border: "none", borderRadius: "4px",
              fontWeight: 600, cursor: state === "scanning" ? "default" : "pointer",
              fontSize: "0.85rem", fontFamily: "monospace",
            }}
          >
            {state === "scanning" ? "Scanning..." : "Scan"}
          </button>
        </div>
        <div style={{ marginTop: "0.5rem", fontSize: "0.72rem", color: "#555" }}>
          Scans HTTPS endpoints only. Private/internal addresses are blocked. 10 scans/min limit.
        </div>
      </div>

      {/* Scanning state */}
      {state === "scanning" && (
        <div style={{ padding: "2rem", background: "#111", borderRadius: "6px", textAlign: "center" }}>
          <div style={{ color: "#0080ff", marginBottom: "0.5rem", fontSize: "0.9rem" }}>
            Probing TLS handshake...
          </div>
          <div style={{ color: "#555", fontSize: "0.8rem" }}>
            Checking key exchange · cert signing algorithm · TLS version
          </div>
        </div>
      )}

      {/* Error state */}
      {state === "error" && (
        <div style={{ padding: "1rem", background: "#ff444418", border: "1px solid #ff444433", borderRadius: "6px" }}>
          <span style={{ color: "#ff4444", fontSize: "0.85rem" }}>{errorMsg}</span>
        </div>
      )}

      {/* Results */}
      {state === "result" && result && (
        <div>
          {/* Score + metadata */}
          <div style={{
            display: "grid", gridTemplateColumns: "200px 1fr", gap: "1rem",
            background: "#111", borderRadius: "6px", padding: "1.5rem", marginBottom: "1rem",
          }}>
            <ScoreGauge score={result.qs_score} />
            <div style={{ fontSize: "0.8rem", lineHeight: 2 }}>
              <div>
                <span style={{ color: "#555" }}>Target: </span>
                <span style={{ color: "#ccc" }}>{result.hostname}</span>
              </div>
              <div>
                <span style={{ color: "#555" }}>TLS: </span>
                <span style={{ color: "#ccc" }}>{result.tls_version}</span>
                <span style={{ color: "#555" }}> · Cipher: </span>
                <code style={{ color: "#ccc", fontSize: "0.75rem" }}>{result.cipher_suite}</code>
              </div>
              <div>
                <span style={{ color: "#555" }}>Key Exchange: </span>
                <code style={{ color: "#f59e0b", fontSize: "0.75rem" }}>{result.key_exchange}</code>
              </div>
              <div>
                <span style={{ color: "#555" }}>Cert Sig Alg: </span>
                <code style={{ color: "#f59e0b", fontSize: "0.75rem" }}>{result.cert_sig_alg}</code>
              </div>
              <div>
                <span style={{ color: "#555" }}>HNDL Risk: </span>
                <span style={{
                  color: HNDL_COLORS[result.hndl_risk],
                  fontWeight: 700, fontSize: "0.75rem",
                }}>
                  {result.hndl_risk.toUpperCase()}
                </span>
              </div>
              <div>
                <span style={{ color: "#555" }}>Scanned: </span>
                <span style={{ color: "#555", fontSize: "0.75rem" }}>
                  {new Date(result.timestamp).toLocaleString()} ({result.scan_duration_ms}ms)
                </span>
              </div>
            </div>
          </div>

          {/* Findings */}
          <div style={{ marginBottom: "1rem" }}>
            <div style={{ fontSize: "0.7rem", color: "#555", textTransform: "uppercase", letterSpacing: "0.1em", marginBottom: "0.5rem" }}>
              Findings ({result.findings.length})
            </div>
            {result.findings.map((f, i) => (
              <FindingCard key={i} finding={f} />
            ))}
          </div>

          {/* Recommendations */}
          {result.recommendation_summary.length > 0 && (
            <div style={{
              background: "#0080ff0a", border: "1px solid #0080ff22",
              borderRadius: "6px", padding: "1rem", marginBottom: "1rem",
            }}>
              <div style={{ fontSize: "0.7rem", color: "#0080ff", textTransform: "uppercase", letterSpacing: "0.1em", marginBottom: "0.5rem" }}>
                Remediation Path
              </div>
              {result.recommendation_summary.map((r, i) => (
                <div key={i} style={{ fontSize: "0.82rem", color: "#ccc", marginBottom: "0.25rem" }}>{r}</div>
              ))}
            </div>
          )}

          {/* NIST refs */}
          <div style={{ borderTop: "1px solid #1a1a1a", paddingTop: "0.75rem" }}>
            <div style={{ fontSize: "0.7rem", color: "#333", textTransform: "uppercase", letterSpacing: "0.1em", marginBottom: "0.4rem" }}>
              References
            </div>
            {result.nist_pqc_refs.map((r, i) => (
              <div key={i} style={{ fontSize: "0.75rem", color: "#444", marginBottom: "0.15rem" }}>{r}</div>
            ))}
          </div>

          {/* Get certified CTA */}
          <div style={{
            marginTop: "1.5rem", padding: "1rem", background: "#00c85310",
            border: "1px solid #00c85333", borderRadius: "6px",
            display: "flex", justifyContent: "space-between", alignItems: "center",
          }}>
            <div>
              <div style={{ fontWeight: 600, fontSize: "0.85rem", color: "#00c853", marginBottom: "0.25rem" }}>
                Ready to certify your quantum posture?
              </div>
              <div style={{ fontSize: "0.78rem", color: "#555" }}>
                AISeal QR-1 and QR-2 certifications go in the public registry — visible to enterprise buyers.
              </div>
            </div>
            <a
              href="/registry/apply"
              style={{
                padding: "0.5rem 1rem", background: "#00c853", color: "#000",
                borderRadius: "4px", fontWeight: 700, fontSize: "0.8rem",
                textDecoration: "none", whiteSpace: "nowrap",
              }}
            >
              Apply →
            </a>
          </div>
        </div>
      )}

      {/* Idle explainer */}
      {state === "idle" && (
        <div style={{ marginTop: "2rem" }}>
          <div style={{ fontSize: "0.7rem", color: "#555", textTransform: "uppercase", letterSpacing: "0.1em", marginBottom: "0.75rem" }}>
            What Gets Checked
          </div>
          <div style={{ display: "grid", gap: "0.5rem" }}>
            {[
              ["TLS Key Exchange", "ECDH/ECDHE/DHE = quantum-vulnerable via Shor's algorithm. ML-KEM = safe."],
              ["Certificate Signing", "RSA and ECDSA certs can be forged by quantum computers. ML-DSA/SLH-DSA = safe."],
              ["TLS Version", "TLS 1.3 required for post-quantum cipher suite negotiation."],
              ["HNDL Exposure", "Nation-states archive traffic today to decrypt later. High-sensitivity sectors = elevated risk."],
            ].map(([check, desc]) => (
              <div key={check} style={{ display: "flex", gap: "0.75rem", padding: "0.6rem", background: "#111", borderRadius: "4px" }}>
                <div style={{ fontWeight: 600, fontSize: "0.8rem", minWidth: "180px", color: "#ccc" }}>{check}</div>
                <div style={{ fontSize: "0.78rem", color: "#555" }}>{desc}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
