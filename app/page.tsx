import Link from "next/link";
import { getCertified, getRegistryStats } from "../lib/registry";

export default function Home() {
  const certs = getCertified().slice(0, 3);
  const stats = getRegistryStats();

  return (
    <div style={{ background: "var(--bg-base)" }}>

      {/* ─────────────────────────── HERO ─────────────────────────── */}
      <section
        className="flex flex-col items-center justify-center text-center px-6 py-28"
        style={{
          background:
            "radial-gradient(ellipse 90% 55% at 50% -10%, rgba(0,128,255,0.1) 0%, rgba(0,200,83,0.05) 50%, transparent 70%)",
          borderBottom: "1px solid var(--border-subtle)",
        }}
      >
        <div
          className="inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-medium mb-6"
          style={{
            background: "rgba(0,200,83,0.08)",
            border: "1px solid rgba(0,200,83,0.2)",
            color: "#00c853",
          }}
        >
          <span className="w-1.5 h-1.5 rounded-full animate-pulse" style={{ background: "#00c853" }} />
          Private Pilot Program — Now Accepting Applications
        </div>

        <h1
          className="text-5xl md:text-6xl font-bold mb-5 max-w-3xl"
          style={{ color: "var(--text-primary)", letterSpacing: "-0.035em", lineHeight: "1.05" }}
        >
          The CA Layer
          <br />
          <span style={{ color: "#0080ff" }}>AI Trust Has Been Missing</span>
        </h1>

        <p className="text-lg md:text-xl max-w-2xl mb-4" style={{ color: "var(--text-secondary)", lineHeight: "1.65" }}>
          Every AI vendor says their product is safe.
          They&apos;re all right — according to themselves.
        </p>
        <p className="text-lg md:text-xl max-w-xl mb-10 font-semibold" style={{ color: "var(--text-primary)" }}>
          AISeal is the independent third party that verifies the claim and makes it public.
        </p>

        <div className="flex items-center gap-4 flex-wrap justify-center mb-10">
          <Link
            href="/registry/apply"
            className="px-7 py-3.5 rounded-md font-semibold text-sm"
            style={{ background: "#00c853", color: "#000000", textDecoration: "none" }}
          >
            Apply for Certification
          </Link>
          <Link
            href="/registry"
            className="px-7 py-3.5 rounded-md font-semibold text-sm"
            style={{
              background: "transparent",
              color: "var(--text-primary)",
              border: "1px solid var(--border-mid)",
              textDecoration: "none",
            }}
          >
            Browse the Registry
          </Link>
        </div>

        {/* Framework pills */}
        <div className="flex flex-wrap gap-2 justify-center">
          {["OWASP LLM Top 10", "NIST AI RMF", "EU AI Act", "MITRE ATLAS"].map((f) => (
            <span
              key={f}
              className="text-xs px-3 py-1 rounded-full font-medium"
              style={{ background: "var(--bg-surface)", border: "1px solid var(--border-mid)", color: "var(--text-muted)" }}
            >
              {f}
            </span>
          ))}
        </div>
      </section>

      {/* ─────────────────────────── THE GAP ─────────────────────────── */}
      <section
        className="px-6 py-20"
        style={{ borderBottom: "1px solid var(--border-subtle)" }}
      >
        <div className="max-w-5xl mx-auto">
          <div className="text-center mb-12">
            <p className="text-xs font-semibold uppercase tracking-widest mb-3" style={{ color: "#f85149" }}>
              The Problem
            </p>
            <h2
              className="text-3xl md:text-4xl font-bold mb-4"
              style={{ color: "var(--text-primary)", letterSpacing: "-0.025em" }}
            >
              Self-attestation doesn&apos;t scale.
            </h2>
            <p className="text-base max-w-xl mx-auto" style={{ color: "var(--text-muted)", lineHeight: "1.7" }}>
              Security teams, compliance teams, and procurement teams all need to trust
              AI systems — but the only evidence they get is marketing copy.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
            {[
              {
                icon: "✗",
                color: "#f85149",
                title: "No independent verification",
                body: "Every AI vendor grades their own homework. Security questionnaires go to the same team that built the product.",
              },
              {
                icon: "✗",
                color: "#f85149",
                title: "No public audit trail",
                body: "Security claims live in PDFs buried in vendor portals. There is no public record, no version history, no verification timestamp.",
              },
              {
                icon: "✗",
                color: "#f85149",
                title: "No revocation mechanism",
                body: "When an AI system\u2019s posture changes — new model, new feature, new vulnerability — old attestations remain valid forever.",
              },
            ].map((item) => (
              <div
                key={item.title}
                className="rounded-xl p-5 flex flex-col gap-3"
                style={{ background: "var(--bg-surface)", border: "1px solid rgba(248,81,73,0.15)" }}
              >
                <span className="text-xl font-bold" style={{ color: item.color }}>{item.icon}</span>
                <h3 className="font-bold text-sm" style={{ color: "var(--text-primary)" }}>{item.title}</h3>
                <p className="text-sm leading-relaxed" style={{ color: "var(--text-muted)" }}>{item.body}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ─────────────────────────── CA MODEL ─────────────────────────── */}
      <section
        className="px-6 py-20"
        style={{ borderBottom: "1px solid var(--border-subtle)" }}
      >
        <div className="max-w-5xl mx-auto">
          <div className="text-center mb-14">
            <p className="text-xs font-semibold uppercase tracking-widest mb-3" style={{ color: "#0080ff" }}>
              The Model
            </p>
            <h2
              className="text-3xl md:text-4xl font-bold mb-5"
              style={{ color: "var(--text-primary)", letterSpacing: "-0.025em" }}
            >
              The CA doesn&apos;t replace your security stack.
              <br />
              <span style={{ color: "#0080ff" }}>It validates it.</span>
            </h2>
            <p className="text-base max-w-2xl mx-auto" style={{ color: "var(--text-muted)", lineHeight: "1.7" }}>
              DigiCert verifies websites. UL certifies consumer products. The FDA certifies
              drugs. None of them compete with the product they certify — they make it credible.
              AISeal is the certification authority for AI.
            </p>
          </div>

          {/* CA flow diagram */}
          <div className="flex flex-col md:flex-row items-center justify-center gap-3 md:gap-0 mb-14">
            {/* Box 1 */}
            <div
              className="rounded-xl p-5 text-center w-full md:w-52 flex-shrink-0"
              style={{ background: "var(--bg-surface)", border: "1px solid var(--border-mid)" }}
            >
              <p className="text-xs font-semibold uppercase tracking-wider mb-2" style={{ color: "var(--text-muted)" }}>
                Security Platforms
              </p>
              <p className="text-sm font-semibold" style={{ color: "var(--text-primary)" }}>
                Prisma AIRS
              </p>
              <p className="text-sm" style={{ color: "var(--text-muted)" }}>HiddenLayer</p>
              <p className="text-sm" style={{ color: "var(--text-muted)" }}>Lakera</p>
              <p className="text-xs mt-3 px-2 py-0.5 rounded-full inline-block" style={{ background: "rgba(0,128,255,0.08)", color: "#0080ff", border: "1px solid rgba(0,128,255,0.2)" }}>
                Telemetry &amp; Defense
              </p>
            </div>

            <ArrowRight />

            {/* Box 2 — AISeal */}
            <div
              className="rounded-xl p-5 text-center w-full md:w-52 flex-shrink-0 relative"
              style={{
                background: "rgba(0,200,83,0.06)",
                border: "2px solid rgba(0,200,83,0.4)",
              }}
            >
              <p className="text-xs font-semibold uppercase tracking-wider mb-2" style={{ color: "#00c853" }}>
                AISeal CA
              </p>
              <p className="font-bold" style={{ color: "var(--text-primary)" }}>Independent</p>
              <p className="font-bold" style={{ color: "var(--text-primary)" }}>Verification</p>
              <p className="text-xs mt-3 px-2 py-0.5 rounded-full inline-block" style={{ background: "rgba(0,200,83,0.1)", color: "#00c853", border: "1px solid rgba(0,200,83,0.3)" }}>
                Public Registry
              </p>
            </div>

            <ArrowRight />

            {/* Box 3 */}
            <div
              className="rounded-xl p-5 text-center w-full md:w-52 flex-shrink-0"
              style={{ background: "var(--bg-surface)", border: "1px solid var(--border-mid)" }}
            >
              <p className="text-xs font-semibold uppercase tracking-wider mb-2" style={{ color: "var(--text-muted)" }}>
                Enterprise Buyers
              </p>
              <p className="text-sm font-semibold" style={{ color: "var(--text-primary)" }}>
                Compliance
              </p>
              <p className="text-sm" style={{ color: "var(--text-muted)" }}>Procurement</p>
              <p className="text-sm" style={{ color: "var(--text-muted)" }}>Security Teams</p>
              <p className="text-xs mt-3 px-2 py-0.5 rounded-full inline-block" style={{ background: "rgba(0,200,83,0.08)", color: "#00c853", border: "1px solid rgba(0,200,83,0.2)" }}>
                Verified Trust
              </p>
            </div>
          </div>

          {/* Quote */}
          <blockquote
            className="max-w-2xl mx-auto text-center rounded-xl px-8 py-6"
            style={{ background: "var(--bg-surface)", border: "1px solid var(--border-mid)" }}
          >
            <p className="text-base leading-relaxed mb-4" style={{ color: "var(--text-secondary)" }}>
              &ldquo;When you visit a secure site, you aren&apos;t just trusting the company behind
              the website — you&apos;re trusting DigiCert or Sectigo to verify them.
              The CA is independent. That independence is the whole point.
              The CA doesn&apos;t replace the firewall. <strong style={{ color: "var(--text-primary)" }}>The CA validates it.</strong>&rdquo;
            </p>
            <p className="text-xs font-semibold" style={{ color: "var(--text-muted)" }}>— The AISeal CA Model</p>
          </blockquote>
        </div>
      </section>

      {/* ─────────────────────────── THREE PRODUCTS ─────────────────────────── */}
      <section className="px-6 py-20" style={{ borderBottom: "1px solid var(--border-subtle)" }}>
        <div className="max-w-5xl mx-auto">
          <div className="text-center mb-12">
            <p className="text-xs font-semibold uppercase tracking-widest mb-3" style={{ color: "#0080ff" }}>
              The Platform
            </p>
            <h2
              className="text-3xl font-bold"
              style={{ color: "var(--text-primary)", letterSpacing: "-0.025em" }}
            >
              Scan it. Certify it. Trust it.
            </h2>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <ProductCard
              step="01"
              icon={<ScanIcon />}
              title="AISeal Scan"
              badge="OWASP LLM Top 10"
              badgeColor="#0080ff"
              description="Automated red-team scanning against all 10 OWASP LLM vulnerabilities. TrustScore 0–100 in minutes. The baseline for every certification."
              cta="Run a Free Scan"
              href="/scan"
              accent="#0080ff"
            />
            <ProductCard
              step="02"
              icon={<CertIcon />}
              title="AISeal Cert"
              badge="Annual Certification"
              badgeColor="#00c853"
              description="Third-party AI vendor certification. Independently assessed, publicly listed, annually recertified. The SOC 2 for AI systems."
              cta="Apply for Certification"
              href="/registry/apply"
              accent="#00c853"
            />
            <ProductCard
              step="03"
              icon={<MonitorIcon />}
              title="AISeal Monitor"
              badge="Runtime Behavioral"
              badgeColor="#a855f7"
              description="Production-grade behavioral proxy for LLM traffic. Real-time anomaly detection, prompt injection alerts, and full audit logging."
              cta="Preview Demo"
              href="/monitor"
              accent="#a855f7"
            />
          </div>
        </div>
      </section>

      {/* ─────────────────────────── LIVE REGISTRY PREVIEW ─────────────────────────── */}
      <section
        className="px-6 py-20"
        style={{ borderBottom: "1px solid var(--border-subtle)" }}
      >
        <div className="max-w-5xl mx-auto">
          <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 mb-10">
            <div>
              <p className="text-xs font-semibold uppercase tracking-widest mb-2" style={{ color: "#00c853" }}>
                Live Registry
              </p>
              <h2
                className="text-3xl font-bold"
                style={{ color: "var(--text-primary)", letterSpacing: "-0.025em" }}
              >
                AI systems you can trust.
              </h2>
              <p className="text-sm mt-2" style={{ color: "var(--text-muted)" }}>
                {stats.total_vendors} certified vendors · {stats.active_certifications} active certifications · updated in real time
              </p>
            </div>
            <Link
              href="/registry"
              className="text-sm font-semibold flex-shrink-0"
              style={{ color: "#0080ff", textDecoration: "none" }}
            >
              Browse full registry →
            </Link>
          </div>

          {/* Registry preview cards */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-10">
            {certs.map((cert) => (
              <RegistryPreviewCard key={cert.cert_id} cert={cert} />
            ))}
          </div>

          {/* Enterprise buyer callout */}
          <div
            className="rounded-xl p-6 flex flex-col md:flex-row items-start md:items-center justify-between gap-5"
            style={{ background: "var(--bg-surface)", border: "1px solid var(--border-mid)" }}
          >
            <div className="flex flex-col gap-3 flex-1">
              <p className="text-xs font-semibold uppercase tracking-widest" style={{ color: "var(--text-muted)" }}>
                For Enterprise Buyers
              </p>
              <p className="font-bold text-base" style={{ color: "var(--text-primary)" }}>
                Your procurement team checks this registry before signing AI vendor contracts.
              </p>
              <div className="flex flex-wrap gap-4 mt-1">
                {[
                  "Compliance: EU AI Act Article 9 documentation",
                  "Procurement: Third-party verified, not self-attested",
                  "Security: Framework coverage and TrustScore on record",
                ].map((item) => (
                  <span key={item} className="flex items-start gap-1.5 text-xs" style={{ color: "var(--text-muted)" }}>
                    <span style={{ color: "#00c853", flexShrink: 0 }}>✓</span>
                    {item}
                  </span>
                ))}
              </div>
            </div>
            <Link
              href="/registry"
              className="px-5 py-2.5 rounded-md text-sm font-semibold flex-shrink-0"
              style={{
                background: "transparent",
                color: "var(--text-primary)",
                border: "1px solid var(--border-mid)",
                textDecoration: "none",
              }}
            >
              Open Registry
            </Link>
          </div>
        </div>
      </section>

      {/* ─────────────────────────── EU AI ACT ─────────────────────────── */}
      <section className="px-6 py-14" style={{ borderBottom: "1px solid var(--border-subtle)" }}>
        <div
          className="max-w-5xl mx-auto rounded-xl p-7 flex flex-col md:flex-row items-center justify-between gap-6"
          style={{
            background: "rgba(0,128,255,0.04)",
            border: "1px solid rgba(0,128,255,0.2)",
          }}
        >
          <div>
            <div className="flex items-center gap-2 mb-2">
              <span className="text-xs font-semibold uppercase tracking-widest" style={{ color: "#0080ff" }}>
                ⚖ EU AI Act — August 2026
              </span>
            </div>
            <h3 className="text-xl font-bold mb-2" style={{ color: "var(--text-primary)" }}>
              High-risk AI systems will require documented evidence. Are you ready?
            </h3>
            <p className="text-sm" style={{ color: "var(--text-muted)" }}>
              AISeal Cert maps directly to Article 9 risk management requirements and generates the
              compliance documentation you need before the deadline.
            </p>
          </div>
          <Link
            href="/registry/apply"
            className="whitespace-nowrap px-6 py-3 rounded-md font-semibold text-sm flex-shrink-0"
            style={{ background: "#0080ff", color: "#ffffff", textDecoration: "none" }}
          >
            Get Ahead of It
          </Link>
        </div>
      </section>

      {/* ─────────────────────────── APPLY CTA ─────────────────────────── */}
      <section className="px-6 py-24">
        <div className="max-w-3xl mx-auto text-center">
          <div
            className="inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-medium mb-6"
            style={{
              background: "rgba(0,200,83,0.08)",
              border: "1px solid rgba(0,200,83,0.2)",
              color: "#00c853",
            }}
          >
            <span className="w-1.5 h-1.5 rounded-full" style={{ background: "#00c853" }} />
            Private Pilot Program — Limited Spots
          </div>

          <h2
            className="text-4xl font-bold mb-5"
            style={{ color: "var(--text-primary)", letterSpacing: "-0.03em", lineHeight: "1.1" }}
          >
            Your AI product
            <br />
            <span style={{ color: "#00c853" }}>should be in this registry.</span>
          </h2>

          <p className="text-base max-w-xl mx-auto mb-8" style={{ color: "var(--text-muted)", lineHeight: "1.7" }}>
            Enterprise procurement teams check this registry before signing AI vendor contracts.
            First-mover advantage is real. Certification starts with a free TrustScan —
            results in minutes, no commitment required.
          </p>

          <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
            <Link
              href="/registry/apply"
              className="px-8 py-4 rounded-md font-semibold text-base"
              style={{ background: "#00c853", color: "#000000", textDecoration: "none" }}
            >
              Apply for Certification
            </Link>
            <Link
              href="/scan"
              className="px-8 py-4 rounded-md font-semibold text-base"
              style={{
                background: "transparent",
                color: "var(--text-primary)",
                border: "1px solid var(--border-mid)",
                textDecoration: "none",
              }}
            >
              Run a Free Scan First
            </Link>
          </div>

          <p className="text-xs mt-5" style={{ color: "var(--text-muted)" }}>
            No commitment. No credit card. We&apos;ll review your application and reach out within 5 business days.
          </p>
        </div>
      </section>
    </div>
  );
}

// ─────────────────────────── REGISTRY PREVIEW CARD ───────────────────────────

import type { CertRecord } from "../lib/registry";

const TIER_META: Record<string, { label: string; color: string }> = {
  "ACF-1": { label: "ACF-1 Verified", color: "#9ca3af" },
  "ACF-2": { label: "ACF-2 Assured", color: "#0080ff" },
  "ACF-3": { label: "ACF-3 Certified", color: "#d4a017" },
};

const STATUS_DOT: Record<string, string> = {
  ACTIVE: "#00c853",
  UNDER_REVIEW: "#f59e0b",
  SUSPENDED: "#f85149",
  EXPIRED: "#6b7280",
};

function scoreColor(s: number): string {
  if (s <= 54) return "#f85149";
  if (s <= 74) return "#f59e0b";
  if (s <= 89) return "#0080ff";
  return "#00c853";
}

function RegistryPreviewCard({ cert }: { cert: CertRecord }) {
  const tier = TIER_META[cert.tier] ?? TIER_META["ACF-1"];
  const dot = STATUS_DOT[cert.status] ?? "#6b7280";

  return (
    <Link href={`/registry/${cert.vendor_id}`} style={{ textDecoration: "none" }} className="block group">
      <div
        className="rounded-xl p-5 flex flex-col gap-3 h-full transition-all"
        style={{ background: "var(--bg-surface)", border: "1px solid var(--border-mid)" }}
      >
        <div className="flex items-start justify-between">
          <div
            className="w-9 h-9 rounded-lg flex items-center justify-center font-bold text-sm"
            style={{ background: `${cert.logo_color}20`, color: cert.logo_color, border: `1px solid ${cert.logo_color}30` }}
          >
            {cert.logo_initial}
          </div>
          <span
            className="text-xs px-2 py-0.5 rounded-full font-medium flex items-center gap-1"
            style={{ background: `${dot}15`, color: dot, border: `1px solid ${dot}25` }}
          >
            <span className="w-1.5 h-1.5 rounded-full" style={{ background: dot }} />
            {cert.status === "ACTIVE" ? "Active" : "Under Review"}
          </span>
        </div>
        <div>
          <p className="font-semibold text-sm" style={{ color: "var(--text-primary)" }}>{cert.vendor_name}</p>
          <p className="text-xs" style={{ color: "var(--text-muted)" }}>{cert.product_name} {cert.product_version}</p>
        </div>
        <div className="flex items-center justify-between mt-auto">
          <span
            className="text-xs px-2 py-0.5 rounded-md font-semibold"
            style={{ background: `${tier.color}15`, color: tier.color, border: `1px solid ${tier.color}25` }}
          >
            {tier.label}
          </span>
          <span className="text-xl font-bold" style={{ color: scoreColor(cert.trust_score) }}>
            {cert.trust_score}
          </span>
        </div>
      </div>
    </Link>
  );
}

// ─────────────────────────── PRODUCT CARD ───────────────────────────

function ProductCard({
  step,
  icon,
  title,
  badge,
  badgeColor,
  description,
  cta,
  href,
  accent,
}: {
  step: string;
  icon: React.ReactNode;
  title: string;
  badge: string;
  badgeColor: string;
  description: string;
  cta: string;
  href: string;
  accent: string;
}) {
  return (
    <div
      className="rounded-xl p-6 flex flex-col gap-4"
      style={{ background: "var(--bg-surface)", border: "1px solid var(--border-mid)" }}
    >
      <div className="flex items-center gap-3">
        <span className="text-xs font-bold" style={{ color: "var(--text-muted)" }}>{step}</span>
        <div
          className="w-9 h-9 rounded-lg flex items-center justify-center"
          style={{ background: `${accent}18`, border: `1px solid ${accent}30` }}
        >
          <span style={{ color: accent }}>{icon}</span>
        </div>
      </div>
      <div>
        <div className="flex items-center gap-2 mb-1.5">
          <h3 className="font-bold text-base" style={{ color: "var(--text-primary)" }}>{title}</h3>
          <span
            className="text-xs px-2 py-0.5 rounded-full font-medium"
            style={{ background: `${badgeColor}15`, color: badgeColor, border: `1px solid ${badgeColor}25` }}
          >
            {badge}
          </span>
        </div>
        <p className="text-sm leading-relaxed" style={{ color: "var(--text-muted)" }}>{description}</p>
      </div>
      <div className="mt-auto">
        <Link
          href={href}
          className="inline-flex items-center gap-1 text-sm font-semibold"
          style={{ color: accent, textDecoration: "none" }}
        >
          {cta} →
        </Link>
      </div>
    </div>
  );
}

// ─────────────────────────── ICONS ───────────────────────────

function ArrowRight() {
  return (
    <div className="flex items-center justify-center w-10 flex-shrink-0 my-2 md:my-0">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" style={{ color: "var(--text-muted)" }}>
        <path
          d="M5 12H19M13 6L19 12L13 18"
          stroke="currentColor"
          strokeWidth="1.5"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
    </div>
  );
}

function ScanIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
      <circle cx="11" cy="11" r="7" stroke="currentColor" strokeWidth="1.5" />
      <path d="M20 20L17 17" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
      <path d="M11 8V11L13 13" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function MonitorIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
      <rect x="2" y="3" width="20" height="14" rx="2" stroke="currentColor" strokeWidth="1.5" />
      <path d="M8 21H16M12 17V21" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
      <path d="M6 10L9 7L12 10L15 6L18 9" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function CertIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
      <path d="M12 2L4 6V12C4 16.4 7.4 20.5 12 22C16.6 20.5 20 16.4 20 12V6L12 2Z"
        stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round" />
      <path d="M9 12L11 14L15 10" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}
