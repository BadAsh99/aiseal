import type { Metadata } from "next";
import { notFound } from "next/navigation";
import Link from "next/link";
import { getCertByVendorId, getCertified } from "../../../lib/registry";
import type { CertTier, CertStatus } from "../../../lib/registry";
import CertBadge from "../../components/registry/CertBadge";
import TrustScoreGauge from "../../components/registry/TrustScoreGauge";
import EmbedCodeBlock from "./EmbedCodeBlock";
import LiveStatusBadge from "./LiveStatusBadge";

export const revalidate = 60;

export async function generateStaticParams() {
  const certs = getCertified();
  return certs.map((c) => ({ vendor_id: c.vendor_id }));
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ vendor_id: string }>;
}): Promise<Metadata> {
  const { vendor_id } = await params;
  const cert = getCertByVendorId(vendor_id);
  if (!cert) return { title: "Certificate Not Found — AISeal" };
  return {
    title: `${cert.vendor_name} — AISeal ${cert.tier} Certificate`,
    description: `${cert.product_name} ${cert.product_version} holds AISeal ${cert.tier} certification with a TrustScore of ${cert.trust_score}/100.`,
  };
}

const TIER_META: Record<CertTier, { label: string; color: string; bg: string; border: string; fullName: string }> = {
  "ACF-1": {
    label: "ACF-1",
    fullName: "ACF-1 Verified",
    color: "#9ca3af",
    bg: "rgba(156,163,175,0.08)",
    border: "rgba(156,163,175,0.2)",
  },
  "ACF-2": {
    label: "ACF-2",
    fullName: "ACF-2 Assured",
    color: "#0080ff",
    bg: "rgba(0,128,255,0.08)",
    border: "rgba(0,128,255,0.2)",
  },
  "ACF-3": {
    label: "ACF-3",
    fullName: "ACF-3 Certified",
    color: "#d4a017",
    bg: "rgba(212,160,23,0.08)",
    border: "rgba(212,160,23,0.2)",
  },
};

const STATUS_META: Record<CertStatus, { label: string; color: string }> = {
  ACTIVE:       { label: "Active",       color: "#00c853" },
  UNDER_REVIEW: { label: "Under Review", color: "#f59e0b" },
  SUSPENDED:    { label: "Suspended",    color: "#f85149" },
  EXPIRED:      { label: "Expired",      color: "#6b7280" },
};

function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString("en-US", {
    month: "long",
    day: "numeric",
    year: "numeric",
  });
}

function CheckRow({ label, checked }: { label: string; checked: boolean }) {
  return (
    <div
      className="flex items-center justify-between px-4 py-3 rounded-lg"
      style={{
        background: checked ? "rgba(0,200,83,0.04)" : "rgba(107,114,128,0.04)",
        border: `1px solid ${checked ? "rgba(0,200,83,0.15)" : "rgba(107,114,128,0.12)"}`,
      }}
    >
      <span className="text-sm font-medium" style={{ color: checked ? "var(--text-primary)" : "var(--text-muted)" }}>
        {label}
      </span>
      <div
        className="w-5 h-5 rounded-full flex items-center justify-center flex-shrink-0"
        style={{
          background: checked ? "rgba(0,200,83,0.15)" : "rgba(107,114,128,0.1)",
          border: `1.5px solid ${checked ? "#00c853" : "#4b5563"}`,
        }}
      >
        {checked ? (
          <svg width="10" height="10" viewBox="0 0 12 12" fill="none">
            <path d="M2 6L5 9L10 3" stroke="#00c853" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        ) : (
          <svg width="8" height="8" viewBox="0 0 12 12" fill="none">
            <path d="M3 3L9 9M9 3L3 9" stroke="#4b5563" strokeWidth="1.8" strokeLinecap="round" />
          </svg>
        )}
      </div>
    </div>
  );
}

export default async function VendorCertPage({
  params,
}: {
  params: Promise<{ vendor_id: string }>;
}) {
  const { vendor_id } = await params;
  const cert = getCertByVendorId(vendor_id);
  if (!cert) notFound();

  const tm = TIER_META[cert.tier];
  const sm = STATUS_META[cert.status];
  const verifyUrl = `https://aiseal.ai/api/verify/${cert.cert_id}`;

  return (
    <div style={{ background: "var(--bg-base)", minHeight: "100vh" }}>
      {/* Breadcrumb */}
      <div style={{ borderBottom: "1px solid var(--border-subtle)" }}>
        <div className="max-w-5xl mx-auto px-6 py-3 flex items-center gap-2 text-sm">
          <Link href="/registry" style={{ color: "#0080ff", textDecoration: "none" }}>
            Registry
          </Link>
          <span style={{ color: "var(--text-muted)" }}>/</span>
          <span style={{ color: "var(--text-secondary)" }}>{cert.vendor_name}</span>
        </div>
      </div>

      <div className="max-w-5xl mx-auto px-6 py-12">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">

          {/* Left column — Badge + Quick facts */}
          <div className="flex flex-col gap-6">
            {/* Badge */}
            <div
              className="rounded-xl p-6 flex flex-col items-center gap-4"
              style={{
                background: "var(--bg-surface)",
                border: `1px solid ${tm.border}`,
              }}
            >
              <CertBadge
                vendor_name={cert.vendor_name}
                tier={cert.tier}
                cert_id={cert.cert_id}
                status={cert.status}
                score={cert.trust_score}
                size="lg"
              />
              <div className="w-full pt-4" style={{ borderTop: "1px solid var(--border-subtle)" }}>
                <LiveStatusBadge certId={cert.cert_id} initialStatus={cert.status} />
              </div>
            </div>

            {/* TrustScore gauge */}
            <div
              className="rounded-xl p-6 flex flex-col items-center gap-2"
              style={{ background: "var(--bg-surface)", border: "1px solid var(--border-mid)" }}
            >
              <p className="text-xs font-semibold uppercase tracking-widest self-start" style={{ color: "var(--text-muted)" }}>
                TrustScore
              </p>
              <TrustScoreGauge score={cert.trust_score} size={200} animated={true} />
            </div>

            {/* Verify button */}
            <div
              className="rounded-xl p-5 flex flex-col gap-3"
              style={{ background: "var(--bg-surface)", border: "1px solid var(--border-mid)" }}
            >
              <p className="text-xs font-semibold uppercase tracking-widest" style={{ color: "var(--text-muted)" }}>
                Verify Certificate
              </p>
              <p className="text-xs leading-relaxed" style={{ color: "var(--text-muted)" }}>
                Independently verify this certificate&apos;s authenticity against the AISeal Verification Registry Service.
              </p>
              <a
                href={verifyUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="w-full text-center px-4 py-2.5 rounded-md text-sm font-semibold"
                style={{ background: "#0080ff", color: "#ffffff", textDecoration: "none" }}
              >
                Verify this certificate →
              </a>
              <p className="text-xs font-mono break-all" style={{ color: "var(--text-subtle)" }}>
                {verifyUrl}
              </p>
            </div>
          </div>

          {/* Right column — Details */}
          <div className="lg:col-span-2 flex flex-col gap-6">

            {/* Header */}
            <div>
              <div className="flex flex-wrap items-center gap-3 mb-3">
                <span
                  className="text-xs font-bold px-2.5 py-1 rounded-md"
                  style={{ background: tm.bg, color: tm.color, border: `1px solid ${tm.border}` }}
                >
                  {tm.fullName}
                </span>
                <span
                  className="inline-flex items-center gap-1.5 text-xs font-medium px-2.5 py-1 rounded-full"
                  style={{ background: `${sm.color}12`, color: sm.color, border: `1px solid ${sm.color}25` }}
                >
                  <span className="w-1.5 h-1.5 rounded-full" style={{ background: sm.color }} />
                  {sm.label}
                </span>
              </div>

              <h1
                className="text-3xl font-bold mb-1"
                style={{ color: "var(--text-primary)", letterSpacing: "-0.025em" }}
              >
                {cert.vendor_name}
              </h1>
              <p className="text-lg" style={{ color: "var(--text-secondary)" }}>
                {cert.product_name}{" "}
                <span style={{ color: "var(--text-muted)" }}>{cert.product_version}</span>
              </p>
            </div>

            {/* Cert details */}
            <div
              className="rounded-xl overflow-hidden"
              style={{ border: "1px solid var(--border-mid)" }}
            >
              <div
                className="px-5 py-3"
                style={{ background: "var(--bg-surface)", borderBottom: "1px solid var(--border-mid)" }}
              >
                <p className="text-xs font-semibold uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>
                  Certificate Details
                </p>
              </div>
              <div style={{ background: "var(--bg-elevated)" }}>
                <DetailRow label="Certificate ID" value={cert.cert_id} mono />
                <DetailRow label="Tier" value={tm.fullName} accent={tm.color} />
                <DetailRow label="Product" value={`${cert.product_name} ${cert.product_version}`} />
                <DetailRow label="Industry" value={cert.industry.charAt(0).toUpperCase() + cert.industry.slice(1).replace("-", " ")} />
                <DetailRow label="Issued" value={formatDate(cert.issued_date)} />
                <DetailRow label="Expires" value={formatDate(cert.expiry_date)} last />
              </div>
            </div>

            {/* Scope */}
            <div
              className="rounded-xl overflow-hidden"
              style={{ border: "1px solid var(--border-mid)" }}
            >
              <div
                className="px-5 py-3"
                style={{ background: "var(--bg-surface)", borderBottom: "1px solid var(--border-mid)" }}
              >
                <p className="text-xs font-semibold uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>
                  Certification Scope
                </p>
              </div>
              <div className="px-5 py-4" style={{ background: "var(--bg-elevated)" }}>
                <p className="text-sm leading-relaxed" style={{ color: "var(--text-secondary)" }}>
                  {cert.scope_description}
                </p>
              </div>
            </div>

            {/* Frameworks covered */}
            <div
              className="rounded-xl overflow-hidden"
              style={{ border: "1px solid var(--border-mid)" }}
            >
              <div
                className="px-5 py-3"
                style={{ background: "var(--bg-surface)", borderBottom: "1px solid var(--border-mid)" }}
              >
                <p className="text-xs font-semibold uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>
                  Frameworks Covered
                </p>
              </div>
              <div className="px-5 py-4 flex flex-col gap-2.5" style={{ background: "var(--bg-elevated)" }}>
                <CheckRow label="OWASP LLM Top 10" checked={cert.frameworks.owasp} />
                <CheckRow label="MITRE ATLAS" checked={cert.frameworks.mitreAtlas} />
                <CheckRow label="NIST AI RMF" checked={cert.frameworks.nist} />
                <CheckRow label="EU AI Act" checked={cert.frameworks.euAiAct} />
              </div>
            </div>

            {/* Embed code */}
            <div
              className="rounded-xl overflow-hidden"
              style={{ border: "1px solid var(--border-mid)" }}
            >
              <div
                className="px-5 py-3"
                style={{ background: "var(--bg-surface)", borderBottom: "1px solid var(--border-mid)" }}
              >
                <p className="text-xs font-semibold uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>
                  Embed Badge
                </p>
              </div>
              <div className="px-5 py-4" style={{ background: "var(--bg-elevated)" }}>
                <p className="text-xs mb-3" style={{ color: "var(--text-muted)" }}>
                  Add this HTML to your website or documentation to display a live-verified AISeal badge.
                </p>
                <EmbedCodeBlock certId={cert.cert_id} vendorId={cert.vendor_id} tier={cert.tier} score={cert.trust_score} />
              </div>
            </div>

            {/* Download cert PDF */}
            <div className="flex flex-wrap gap-3">
              <a
                href={`/api/cert/${cert.cert_id}/pdf`}
                className="inline-flex items-center gap-2 px-5 py-2.5 rounded-md text-sm font-semibold"
                style={{
                  background: "var(--bg-surface)",
                  color: "var(--text-primary)",
                  border: "1px solid var(--border-mid)",
                  textDecoration: "none",
                }}
              >
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none">
                  <path d="M12 16L12 4M12 16L8 12M12 16L16 12" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                  <path d="M4 20H20" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
                </svg>
                Download Certificate PDF
              </a>
              <Link
                href="/registry"
                className="inline-flex items-center gap-2 px-5 py-2.5 rounded-md text-sm font-semibold"
                style={{
                  background: "transparent",
                  color: "var(--text-muted)",
                  textDecoration: "none",
                }}
              >
                ← Back to Registry
              </Link>
            </div>

          </div>
        </div>
      </div>
    </div>
  );
}

function DetailRow({
  label,
  value,
  mono,
  accent,
  last,
}: {
  label: string;
  value: string;
  mono?: boolean;
  accent?: string;
  last?: boolean;
}) {
  return (
    <div
      className="px-5 py-3 flex items-center justify-between gap-4"
      style={{ borderBottom: last ? "none" : "1px solid var(--border-subtle)" }}
    >
      <span className="text-sm" style={{ color: "var(--text-muted)", flexShrink: 0 }}>
        {label}
      </span>
      <span
        className={`text-sm font-medium text-right ${mono ? "font-mono" : ""}`}
        style={{ color: accent ?? "var(--text-primary)" }}
      >
        {value}
      </span>
    </div>
  );
}
