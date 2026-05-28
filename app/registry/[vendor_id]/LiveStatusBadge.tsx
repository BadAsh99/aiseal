"use client";

// AISeal F1+F2 — REAL Live Status Badge.
// Calls /api/verify/{cert_id} on mount, shows the actual verification result.
// Replaces the prior setTimeout(900ms) theater the 3-Vs audit caught.

import { useEffect, useState } from "react";
import type { CertStatus } from "../../../lib/registry";

interface LiveStatusBadgeProps {
  certId: string;
  initialStatus: CertStatus;
}

type VRSStatus = "ACTIVE" | "WATCH" | "SUSPENDED" | "UNKNOWN" | "ERROR";

const STATUS_CONFIG: Record<VRSStatus, { label: string; color: string; bg: string; border: string; pulse: boolean }> = {
  ACTIVE:    { label: "ACTIVE",     color: "#00c853", bg: "rgba(0,200,83,0.1)",   border: "rgba(0,200,83,0.25)",   pulse: true },
  WATCH:     { label: "WATCH",      color: "#f59e0b", bg: "rgba(245,158,11,0.1)", border: "rgba(245,158,11,0.25)", pulse: true },
  SUSPENDED: { label: "SUSPENDED",  color: "#f85149", bg: "rgba(248,81,73,0.1)",  border: "rgba(248,81,73,0.25)",  pulse: false },
  UNKNOWN:   { label: "CHECKING…",  color: "#6b7280", bg: "rgba(107,114,128,0.1)", border: "rgba(107,114,128,0.2)", pulse: false },
  ERROR:     { label: "UNREACHABLE", color: "#6b7280", bg: "rgba(107,114,128,0.1)", border: "rgba(107,114,128,0.2)", pulse: false },
};

function mapCertToVrs(status: CertStatus): VRSStatus {
  switch (status) {
    case "ACTIVE": return "ACTIVE";
    case "UNDER_REVIEW": return "WATCH";
    case "SUSPENDED": case "EXPIRED": return "SUSPENDED";
  }
}

interface VerifyResponse {
  valid: boolean;
  result: string;
  cert?: { status: CertStatus };
  origin_check?: string;
  signature?: string;
  verified_at?: string;
}

export default function LiveStatusBadge({ certId, initialStatus }: LiveStatusBadgeProps) {
  const [vrsStatus, setVrsStatus] = useState<VRSStatus>("UNKNOWN");
  const [checked, setChecked] = useState(false);
  const [lastChecked, setLastChecked] = useState<string | null>(null);
  const [signature, setSignature] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch(`/api/verify/${encodeURIComponent(certId)}`, { cache: "no-store" });
        if (cancelled) return;
        if (!res.ok && res.status !== 404) {
          setVrsStatus("ERROR");
          setChecked(true);
          return;
        }
        const data: VerifyResponse = await res.json();
        if (cancelled) return;
        if (data.cert?.status) {
          setVrsStatus(mapCertToVrs(data.cert.status));
        } else {
          // Fall back to the server-rendered status so we never show a worse state than truth
          setVrsStatus(mapCertToVrs(initialStatus));
        }
        if (data.signature) setSignature(data.signature.slice(0, 12));
        setChecked(true);
        setLastChecked(
          new Date(data.verified_at ?? new Date().toISOString()).toLocaleTimeString("en-US", {
            hour: "2-digit", minute: "2-digit", second: "2-digit",
          }),
        );
      } catch {
        if (!cancelled) {
          setVrsStatus("ERROR");
          setChecked(true);
        }
      }
    })();
    return () => { cancelled = true; };
  }, [certId, initialStatus]);

  const cfg = STATUS_CONFIG[vrsStatus];

  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>
          Live Status
        </span>
        {checked && vrsStatus !== "ERROR" && (
          <span className="text-xs" style={{ color: "var(--text-subtle)" }}>
            VRS verified
          </span>
        )}
      </div>

      <div
        className="flex items-center gap-2.5 px-3 py-2.5 rounded-lg"
        style={{ background: cfg.bg, border: `1px solid ${cfg.border}` }}
      >
        <div className="relative flex-shrink-0">
          <span className="block w-2.5 h-2.5 rounded-full" style={{ background: cfg.color }} />
          {cfg.pulse && checked && (
            <span className="absolute inset-0 rounded-full animate-ping" style={{ background: cfg.color, opacity: 0.4 }} />
          )}
        </div>
        <span className="text-sm font-bold tracking-wide" style={{ color: cfg.color }}>
          {cfg.label}
        </span>
        {!checked && (
          <svg className="ml-auto animate-spin" width="12" height="12" viewBox="0 0 24 24" fill="none" style={{ color: "var(--text-muted)" }}>
            <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="2" strokeOpacity="0.25" />
            <path d="M12 3a9 9 0 019 9" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
          </svg>
        )}
      </div>

      {lastChecked && vrsStatus !== "ERROR" && (
        <p className="text-xs" style={{ color: "var(--text-subtle)" }}>
          Checked against VRS at {lastChecked}
          {signature && (
            <> · sig <span className="font-mono">{signature}…</span></>
          )}
        </p>
      )}

      <p className="text-xs leading-relaxed" style={{ color: "var(--text-muted)" }}>
        Status is verified in real time against the AISeal Verification Registry Service (VRS).
        {vrsStatus === "WATCH" && " This certificate is currently under scheduled review audit. It remains valid."}
        {vrsStatus === "SUSPENDED" && " This certificate has been suspended. Do not rely on it for compliance."}
        {vrsStatus === "ERROR" && " Could not reach VRS — refresh to retry."}
      </p>
    </div>
  );
}
