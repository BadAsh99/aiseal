import Link from "next/link";

export default function Home() {
  return (
    <div style={{ background: "#0a0a0a" }}>
      {/* Hero */}
      <section
        className="flex flex-col items-center justify-center text-center px-6 py-32"
        style={{
          background:
            "radial-gradient(ellipse 80% 50% at 50% -10%, rgba(0,128,255,0.12) 0%, transparent 70%)",
          borderBottom: "1px solid #1a1a1a",
        }}
      >
        <div
          className="inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-medium mb-6"
          style={{
            background: "rgba(0,128,255,0.1)",
            border: "1px solid rgba(0,128,255,0.3)",
            color: "#0080ff",
          }}
        >
          <span
            className="w-1.5 h-1.5 rounded-full"
            style={{ background: "#0080ff" }}
          />
          EU AI Act Enforcement Begins 2026
        </div>

        <h1
          className="text-5xl font-bold tracking-tight mb-4 max-w-2xl"
          style={{
            color: "#ededed",
            letterSpacing: "-0.03em",
            lineHeight: "1.1",
          }}
        >
          AI You Can Trust
        </h1>

        <p
          className="text-xl mb-10 max-w-xl"
          style={{ color: "#9ca3af", lineHeight: "1.6" }}
        >
          The first AI security trust and certification platform.
          <br />
          <span style={{ color: "#ededed" }}>Scan it. Monitor it. Certify it.</span>
        </p>

        <div className="flex items-center gap-4 flex-wrap justify-center">
          <Link
            href="/scan"
            className="px-6 py-3 rounded-md font-semibold text-sm transition-colors"
            style={{ background: "#0080ff", color: "#ffffff", textDecoration: "none" }}
          >
            Run a Free TrustScan
          </Link>
          <Link
            href="/registry"
            className="px-6 py-3 rounded-md font-semibold text-sm"
            style={{
              background: "transparent",
              color: "#ededed",
              border: "1px solid #2a2a2a",
              textDecoration: "none",
            }}
          >
            View Certified Products
          </Link>
        </div>
      </section>

      {/* Problem Statement */}
      <section
        className="px-6 py-20 text-center"
        style={{ borderBottom: "1px solid #1a1a1a" }}
      >
        <div className="max-w-3xl mx-auto">
          <h2
            className="text-3xl font-bold mb-4"
            style={{ color: "#ededed", letterSpacing: "-0.02em" }}
          >
            Every company is deploying AI.
            <br />
            <span style={{ color: "#f85149" }}>Nobody can prove it&apos;s safe.</span>
          </h2>
          <p className="text-lg max-w-2xl mx-auto" style={{ color: "#6b7280" }}>
            OWASP LLM Top 10 vulnerabilities exist in production AI systems today —
            prompt injection, data exfiltration, excessive agency. Security teams have no
            runtime visibility. Procurement teams have no vendor signal. Compliance teams
            have no audit trail.
          </p>
        </div>
      </section>

      {/* Product Cards */}
      <section className="px-6 py-20" style={{ borderBottom: "1px solid #1a1a1a" }}>
        <div className="max-w-5xl mx-auto">
          <p
            className="text-xs font-semibold uppercase tracking-widest mb-3 text-center"
            style={{ color: "#0080ff" }}
          >
            Three Products. One Trust Platform.
          </p>
          <h2
            className="text-3xl font-bold text-center mb-12"
            style={{ color: "#ededed", letterSpacing: "-0.02em" }}
          >
            The complete AI security stack
          </h2>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <ProductCard
              icon={<ScanIcon />}
              title="AISeal Scan"
              badge="OWASP LLM Top 10"
              description="Automated red-team scanning against every OWASP LLM vulnerability. Get a TrustScore in minutes, not months."
              cta="Run a Scan"
              href="/scan"
              accent="#0080ff"
            />
            <ProductCard
              icon={<MonitorIcon />}
              title="AISeal Monitor"
              badge="Coming Soon"
              description="Behavioral proxy for production LLM traffic. Real-time anomaly detection, prompt injection alerts, and full audit logging."
              cta="Join Waitlist"
              href="/scan"
              accent="#a855f7"
            />
            <ProductCard
              icon={<CertIcon />}
              title="AISeal Cert"
              badge="Annual Certification"
              description="Third-party AI vendor certification with a public badge and searchable registry. The SOC 2 for AI systems."
              cta="View Registry"
              href="/registry"
              accent="#00c853"
            />
          </div>
        </div>
      </section>

      {/* EU AI Act Banner */}
      <section className="px-6 py-16">
        <div
          className="max-w-4xl mx-auto rounded-xl p-8 flex flex-col md:flex-row items-center justify-between gap-6"
          style={{
            background: "rgba(0,128,255,0.05)",
            border: "1px solid rgba(0,128,255,0.2)",
          }}
        >
          <div>
            <div className="flex items-center gap-2 mb-2">
              <span style={{ color: "#0080ff", fontSize: "1.25rem" }}>⚖</span>
              <span
                className="text-xs font-semibold uppercase tracking-widest"
                style={{ color: "#0080ff" }}
              >
                EU AI Act — August 2026
              </span>
            </div>
            <h3
              className="text-xl font-bold mb-2"
              style={{ color: "#ededed" }}
            >
              EU AI Act enforcement begins 2026. Are you ready?
            </h3>
            <p className="text-sm" style={{ color: "#6b7280" }}>
              High-risk AI systems will require documented risk assessments, transparency
              obligations, and human oversight mechanisms. AISeal Cert maps directly to
              Article 9 compliance requirements.
            </p>
          </div>
          <Link
            href="/scan"
            className="whitespace-nowrap px-5 py-3 rounded-md font-semibold text-sm flex-shrink-0"
            style={{
              background: "#0080ff",
              color: "#ffffff",
              textDecoration: "none",
            }}
          >
            Assess Your Risk
          </Link>
        </div>
      </section>
    </div>
  );
}

function ProductCard({
  icon,
  title,
  badge,
  description,
  cta,
  href,
  external,
  accent,
}: {
  icon: React.ReactNode;
  title: string;
  badge: string;
  description: string;
  cta: string;
  href: string;
  external?: boolean;
  accent: string;
}) {
  const linkProps = external
    ? { target: "_blank", rel: "noopener noreferrer" }
    : {};

  return (
    <div
      className="rounded-xl p-6 flex flex-col gap-4 transition-all"
      style={{
        background: "#111111",
        border: "1px solid #2a2a2a",
      }}
    >
      <div
        className="w-10 h-10 rounded-lg flex items-center justify-center"
        style={{ background: `${accent}18`, border: `1px solid ${accent}30` }}
      >
        <span style={{ color: accent }}>{icon}</span>
      </div>
      <div>
        <div className="flex items-center gap-2 mb-1">
          <h3 className="font-bold text-base" style={{ color: "#ededed" }}>
            {title}
          </h3>
          <span
            className="text-xs px-2 py-0.5 rounded-full font-medium"
            style={{
              background: `${accent}15`,
              color: accent,
              border: `1px solid ${accent}25`,
            }}
          >
            {badge}
          </span>
        </div>
        <p className="text-sm leading-relaxed" style={{ color: "#6b7280" }}>
          {description}
        </p>
      </div>
      <div className="mt-auto">
        <a
          href={href}
          {...linkProps}
          className="inline-flex items-center gap-1 text-sm font-semibold transition-colors"
          style={{ color: accent, textDecoration: "none" }}
        >
          {cta} →
        </a>
      </div>
    </div>
  );
}

function ScanIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
      <circle cx="11" cy="11" r="7" stroke="currentColor" strokeWidth="1.5" />
      <path d="M20 20L17 17" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
      <path d="M11 8V11L13 13" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function MonitorIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
      <rect x="2" y="3" width="20" height="14" rx="2" stroke="currentColor" strokeWidth="1.5" />
      <path d="M8 21H16M12 17V21" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
      <path d="M6 10L9 7L12 10L15 6L18 9" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function CertIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
      <path
        d="M12 2L4 6V12C4 16.4 7.4 20.5 12 22C16.6 20.5 20 16.4 20 12V6L12 2Z"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinejoin="round"
      />
      <path
        d="M9 12L11 14L15 10"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}
