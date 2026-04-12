import type { Metadata } from "next";
import Link from "next/link";
import { getCertified, getRegistryStats } from "../../lib/registry";
import RegistryClient from "./RegistryClient";

export const revalidate = 60;

export const metadata: Metadata = {
  title: "AI Trust Registry — AISeal",
  description: "The public registry of AI-certified products. Independently verified, annually recertified.",
};

function formatTimestamp(iso: string): string {
  return new Date(iso).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export default function RegistryPage() {
  const certs = getCertified();
  const stats = getRegistryStats();

  return (
    <div style={{ background: "var(--bg-base)", minHeight: "100vh" }}>
      {/* Hero */}
      <section
        className="text-center px-6 py-20"
        style={{
          background:
            "radial-gradient(ellipse 70% 40% at 50% -5%, rgba(0,200,83,0.1) 0%, transparent 65%)",
          borderBottom: "1px solid var(--border-subtle)",
        }}
      >
        <div
          className="inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-medium mb-5"
          style={{
            background: "rgba(0,200,83,0.08)",
            border: "1px solid rgba(0,200,83,0.2)",
            color: "#00c853",
          }}
        >
          <span className="w-1.5 h-1.5 rounded-full" style={{ background: "#00c853" }} />
          Live Registry — Updated in real time
        </div>

        <h1
          className="text-4xl md:text-5xl font-bold mb-4 max-w-2xl mx-auto"
          style={{ color: "var(--text-primary)", letterSpacing: "-0.03em", lineHeight: "1.1" }}
        >
          The AISeal
          <br />
          <span style={{ color: "#00c853" }}>AI Trust Registry</span>
        </h1>

        <p
          className="text-lg max-w-lg mx-auto mb-8"
          style={{ color: "var(--text-secondary)", lineHeight: "1.6" }}
        >
          The authoritative public record of AI systems that have been independently assessed,
          verified, and certified against OWASP LLM Top 10, NIST AI RMF, and EU AI Act standards.
        </p>

        <div className="flex flex-wrap gap-3 justify-center">
          <Link
            href="/scan"
            className="px-5 py-2.5 rounded-md text-sm font-semibold"
            style={{ background: "#00c853", color: "#000000", textDecoration: "none" }}
          >
            Apply for Certification
          </Link>
          <a
            href="#registry"
            className="px-5 py-2.5 rounded-md text-sm font-semibold"
            style={{
              background: "transparent",
              color: "var(--text-primary)",
              border: "1px solid var(--border-mid)",
              textDecoration: "none",
            }}
          >
            Browse Certified Products
          </a>
        </div>
      </section>

      {/* Stats bar */}
      <section style={{ borderBottom: "1px solid var(--border-subtle)" }}>
        <div className="max-w-5xl mx-auto px-6 py-6">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <StatTile
              value={stats.total_vendors.toString()}
              label="Certified Vendors"
              color="#00c853"
            />
            <StatTile
              value={stats.total_certifications.toString()}
              label="Total Certifications"
              color="#0080ff"
            />
            <StatTile
              value={stats.active_certifications.toString()}
              label="Active Certifications"
              color="#00c853"
            />
            <div
              className="rounded-xl px-5 py-4"
              style={{ background: "var(--bg-surface)", border: "1px solid var(--border-mid)" }}
            >
              <p className="text-xs mb-1" style={{ color: "var(--text-muted)" }}>Last Updated</p>
              <p className="text-xs font-semibold" style={{ color: "var(--text-secondary)" }}>
                {formatTimestamp(stats.last_updated)}
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Tier legend */}
      <section style={{ borderBottom: "1px solid var(--border-subtle)" }}>
        <div className="max-w-5xl mx-auto px-6 py-6">
          <p className="text-xs font-semibold uppercase tracking-widest mb-4" style={{ color: "var(--text-muted)" }}>
            Certification Tiers
          </p>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <TierLegendCard
              tier="ACF-1"
              name="Verified"
              color="#9ca3af"
              minScore={75}
              desc="All three mandatory OWASP controls pass. No CRITICAL findings. Baseline AI safety posture confirmed."
            />
            <TierLegendCard
              tier="ACF-2"
              name="Assured"
              color="#0080ff"
              minScore={85}
              desc="All mandatory + applicable conditional controls pass. No CRITICAL or HIGH findings. NIST AI RMF alignment verified."
            />
            <TierLegendCard
              tier="ACF-3"
              name="Certified"
              color="#d4a017"
              minScore={90}
              desc="Full framework coverage including EU AI Act. Ghost99RT runtime monitoring. Annual audit + SLA included."
            />
          </div>
        </div>
      </section>

      {/* Registry */}
      <section id="registry" className="max-w-5xl mx-auto px-6 py-12">
        <div className="flex items-center justify-between mb-8">
          <div>
            <p className="text-xs font-semibold uppercase tracking-widest mb-1" style={{ color: "#00c853" }}>
              Certified Products
            </p>
            <h2
              className="text-2xl font-bold"
              style={{ color: "var(--text-primary)", letterSpacing: "-0.02em" }}
            >
              AI systems you can trust
            </h2>
          </div>
        </div>

        <RegistryClient initialCerts={certs} />

        {/* Bottom CTA */}
        <div
          className="mt-12 rounded-xl p-8 flex flex-col md:flex-row items-start md:items-center gap-6 justify-between"
          style={{
            background: "rgba(0,200,83,0.04)",
            border: "1px solid rgba(0,200,83,0.15)",
          }}
        >
          <div>
            <div className="flex items-center gap-2 mb-2">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none">
                <path
                  d="M12 2L4 6V12C4 16.4 7.4 20.5 12 22C16.6 20.5 20 16.4 20 12V6L12 2Z"
                  fill="rgba(0,200,83,0.15)"
                  stroke="#00c853"
                  strokeWidth="1.5"
                  strokeLinejoin="round"
                />
                <path d="M9 12L11 14L15 10" stroke="#00c853" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
              <span className="text-xs font-semibold uppercase tracking-wide" style={{ color: "#00c853" }}>
                Get Certified
              </span>
            </div>
            <h3 className="text-xl font-bold mb-2" style={{ color: "var(--text-primary)" }}>
              Your AI product should be here.
            </h3>
            <p className="text-sm max-w-md" style={{ color: "var(--text-muted)" }}>
              Certification starts with a free TrustScan. We assess your AI against OWASP LLM Top 10,
              deliver a scored report, and guide you to certification. First-mover advantage is real —
              enterprise procurement teams check this registry.
            </p>
          </div>
          <div className="flex flex-col gap-3 flex-shrink-0">
            <Link
              href="/scan"
              className="px-6 py-3 rounded-md text-sm font-semibold text-center whitespace-nowrap"
              style={{ background: "#00c853", color: "#000000", textDecoration: "none" }}
            >
              Start with a Free Scan
            </Link>
            <p className="text-xs text-center" style={{ color: "var(--text-muted)" }}>
              Results in minutes. No commitment.
            </p>
          </div>
        </div>
      </section>
    </div>
  );
}

function StatTile({ value, label, color }: { value: string; label: string; color: string }) {
  return (
    <div
      className="rounded-xl px-5 py-4"
      style={{ background: "var(--bg-surface)", border: "1px solid var(--border-mid)" }}
    >
      <p className="text-2xl font-bold mb-1" style={{ color }}>
        {value}
      </p>
      <p className="text-xs" style={{ color: "var(--text-muted)" }}>
        {label}
      </p>
    </div>
  );
}

function TierLegendCard({
  tier,
  name,
  color,
  minScore,
  desc,
}: {
  tier: string;
  name: string;
  color: string;
  minScore: number;
  desc: string;
}) {
  return (
    <div
      className="rounded-xl p-4 flex flex-col gap-2"
      style={{
        background: "var(--bg-surface)",
        border: `1px solid ${color}25`,
      }}
    >
      <div className="flex items-center justify-between">
        <span
          className="text-xs font-bold px-2 py-0.5 rounded-md"
          style={{ background: `${color}15`, color, border: `1px solid ${color}30` }}
        >
          {tier}
        </span>
        <span className="text-xs font-semibold" style={{ color }}>
          {minScore}+ score
        </span>
      </div>
      <p className="font-semibold text-sm" style={{ color: "var(--text-primary)" }}>
        {name}
      </p>
      <p className="text-xs leading-relaxed" style={{ color: "var(--text-muted)" }}>
        {desc}
      </p>
    </div>
  );
}
