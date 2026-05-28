import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "Disclosure ≠ Evidence — AISeal",
  description:
    "An AI vendor saying their model is safe is disclosure. Running OWASP LLM Top 10 red-team scans against it and signing the result is evidence. AISeal certifies the evidence.",
  openGraph: {
    title: "Disclosure ≠ Evidence",
    description:
      "AI safety claims aren't audits. AISeal certifies the evidence — OWASP LLM Top 10 scan + HMAC-signed badge + runtime monitoring.",
    siteName: "AISeal",
  },
};

export default function DisclosureVsEvidencePage() {
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
          The market is filling with disclosure registries. AISeal is not one.
        </div>

        <h1
          className="text-4xl md:text-6xl font-bold mb-5 max-w-3xl mx-auto"
          style={{ color: "var(--text-primary)", letterSpacing: "-0.03em", lineHeight: "1.05" }}
        >
          Disclosure{" "}
          <span style={{ color: "var(--text-muted)", fontWeight: 400 }}>≠</span>{" "}
          <span style={{ color: "#00c853" }}>Evidence</span>
        </h1>

        <p
          className="text-lg max-w-2xl mx-auto"
          style={{ color: "var(--text-secondary)", lineHeight: "1.6" }}
        >
          An AI vendor saying their model is safe is disclosure. Running OWASP LLM Top 10 red-team
          scans against it, scoring the findings, and signing the result is evidence. AISeal
          certifies the evidence — and the badge is cryptographically verifiable.
        </p>
      </section>

      {/* Comparison */}
      <section className="max-w-5xl mx-auto px-6 py-16">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div
            className="rounded-xl p-7"
            style={{
              background: "var(--bg-surface)",
              border: "1px solid var(--border-mid)",
            }}
          >
            <p className="text-xs font-bold uppercase tracking-wider mb-2" style={{ color: "var(--text-muted)" }}>
              Disclosure registries
            </p>
            <h2 className="text-2xl font-bold mb-4" style={{ color: "var(--text-primary)" }}>
              Vendors tell you what they do.
            </h2>
            <p className="leading-relaxed mb-4" style={{ color: "var(--text-secondary)" }}>
              The vendor fills out a questionnaire. They describe their model, their guardrails,
              their data handling. The registry publishes it. The buyer reads it. There is no
              independent test of any of those claims.
            </p>
            <ul className="space-y-2 text-sm" style={{ color: "var(--text-muted)" }}>
              <Bullet muted>Vendor self-attests · no independent test</Bullet>
              <Bullet muted>Snapshot in time · drifts as the model is retrained</Bullet>
              <Bullet muted>Trust the form · no cryptographic proof on the badge</Bullet>
              <Bullet muted>No runtime check · the production model is never observed</Bullet>
            </ul>
            <p className="mt-5 text-xs italic" style={{ color: "var(--text-subtle)" }}>
              Useful for transparency. Not enough for procurement.
            </p>
          </div>

          <div
            className="rounded-xl p-7"
            style={{
              background: "rgba(0,200,83,0.04)",
              border: "1px solid rgba(0,200,83,0.25)",
            }}
          >
            <p className="text-xs font-bold uppercase tracking-wider mb-2" style={{ color: "#00c853" }}>
              AISeal certification
            </p>
            <h2 className="text-2xl font-bold mb-4" style={{ color: "var(--text-primary)" }}>
              We test what they ship.
            </h2>
            <p className="leading-relaxed mb-4" style={{ color: "var(--text-secondary)" }}>
              We run OWASP LLM Top 10 red-team prompts against the vendor&apos;s actual model,
              score the result against a defined rubric, map findings to NIST AI RMF + EU AI Act +
              MITRE ATLAS, and issue a tier (ACF-1 / ACF-2 / ACF-3) backed by an HMAC-signed badge
              and a public verify endpoint.
            </p>
            <ul className="space-y-2 text-sm" style={{ color: "var(--text-secondary)" }}>
              <Bullet>OWASP LLM Top 10 + ASI01-10 red-team scan · scored 0-100</Bullet>
              <Bullet>HMAC-signed badge · cryptographically verifiable</Bullet>
              <Bullet>Origin-bound verify endpoint · /api/verify/{`{cert_id}`}</Bullet>
              <Bullet>Annual recert + Ghost99RT runtime monitoring (ACF-3)</Bullet>
            </ul>
            <p className="mt-5 text-xs italic" style={{ color: "#00c853" }}>
              Procurement-grade. Auditor-defensible. Forge-resistant.
            </p>
          </div>
        </div>
      </section>

      {/* Why it matters */}
      <section style={{ borderTop: "1px solid var(--border-subtle)", borderBottom: "1px solid var(--border-subtle)" }}>
        <div className="max-w-4xl mx-auto px-6 py-16">
          <p className="text-xs font-bold uppercase tracking-widest mb-3" style={{ color: "#00c853" }}>
            Why this distinction matters
          </p>
          <h2 className="text-3xl font-bold mb-8" style={{ color: "var(--text-primary)", letterSpacing: "-0.02em" }}>
            The SSL analogy
          </h2>

          <div className="space-y-6 text-base leading-relaxed" style={{ color: "var(--text-secondary)" }}>
            <p>
              In 1995 you could put a padlock icon on your website. It meant nothing — anyone could
              draw one. By 1996 the industry had moved to certificates issued by a Certificate
              Authority that verified domain ownership. The padlock became evidence, not a claim.
              Browsers now refuse to show the padlock without it.
            </p>
            <p>
              AI is in 1995. Every vendor claims their model is safe. Every vendor publishes a
              policy. Procurement teams have no way to distinguish &ldquo;we ran red-team tests&rdquo;
              from &ldquo;we said we ran red-team tests.&rdquo; Disclosure registries make the
              claim shareable. They do not make the claim verifiable.
            </p>
            <p>
              <strong style={{ color: "var(--text-primary)" }}>AISeal is the CA layer for AI.</strong>{" "}
              We run the test. We score the result. We sign the badge. The badge is bound to the
              vendor&apos;s domain via Origin/Referer validation — if someone tries to embed it on
              an uncertified site, the verify endpoint flags an origin mismatch and the badge fails.
            </p>
          </div>
        </div>
      </section>

      {/* What we actually do */}
      <section className="max-w-5xl mx-auto px-6 py-16">
        <p className="text-xs font-bold uppercase tracking-widest text-center mb-3" style={{ color: "#00c853" }}>
          What an AISeal certification involves
        </p>
        <h2
          className="text-3xl font-bold text-center mb-12"
          style={{ color: "var(--text-primary)", letterSpacing: "-0.02em" }}
        >
          Four things a disclosure form can never give you
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
          <Pillar
            number="01"
            title="Red-team scan against the live model"
            body="We send OWASP LLM Top 10 attack prompts to the production endpoint and grade the responses. Prompt injection, sensitive info disclosure, training-data poisoning, model DoS, supply-chain risk, output handling. No self-report — observed behavior."
          />
          <Pillar
            number="02"
            title="Cryptographically signed badge"
            body="The SVG badge embeds an HMAC-SHA256 signature of (cert_id, vendor_domain, score, issued_date). Any byte tampered with breaks the signature. The verify endpoint regenerates it from the canonical cert record and constant-time compares."
          />
          <Pillar
            number="03"
            title="Origin-bound verification"
            body="The verify endpoint checks the Origin/Referer of the request against the certified vendor domain. Embedding the badge on a site the cert doesn't cover returns origin_mismatch — every attempt is logged to verification_log."
          />
          <Pillar
            number="04"
            title="Runtime monitoring (ACF-3)"
            body="Ghost99RT watches the production model for behavioral drift after issuance. If the cert was earned and then quietly degraded, we know. Disclosure registries capture a snapshot; AISeal ACF-3 maintains a posture."
          />
        </div>
      </section>

      {/* CTA */}
      <section
        style={{
          background:
            "linear-gradient(135deg, rgba(0,200,83,0.06) 0%, rgba(0,128,255,0.04) 100%)",
          borderTop: "1px solid var(--border-subtle)",
        }}
      >
        <div className="max-w-3xl mx-auto px-6 py-16 text-center">
          <h2 className="text-3xl font-bold mb-4" style={{ color: "var(--text-primary)" }}>
            Certify the evidence.
          </h2>
          <p className="text-lg mb-8" style={{ color: "var(--text-secondary)" }}>
            Run a free TrustScan against your own AI to see how it scores against OWASP LLM Top 10.
            If you&apos;re ready, apply for an ACF-1, ACF-2, or ACF-3 certification.
          </p>
          <div className="flex flex-wrap gap-3 justify-center">
            <Link
              href="/scan"
              className="px-6 py-3 rounded-md text-sm font-semibold"
              style={{ background: "#00c853", color: "#000000", textDecoration: "none" }}
            >
              Run a free TrustScan →
            </Link>
            <Link
              href="/registry/apply"
              className="px-6 py-3 rounded-md text-sm font-semibold"
              style={{
                background: "transparent",
                color: "var(--text-primary)",
                border: "1px solid var(--border-mid)",
                textDecoration: "none",
              }}
            >
              Apply for certification
            </Link>
            <Link
              href="/registry"
              className="px-6 py-3 rounded-md text-sm font-semibold"
              style={{
                background: "transparent",
                color: "var(--text-secondary)",
                border: "1px solid var(--border-subtle)",
                textDecoration: "none",
              }}
            >
              Browse the registry
            </Link>
          </div>
        </div>
      </section>
    </div>
  );
}

function Bullet({ children, muted = false }: { children: React.ReactNode; muted?: boolean }) {
  return (
    <li className="flex items-start gap-2.5">
      <span style={{ color: muted ? "var(--text-subtle)" : "#00c853" }}>•</span>
      <span>{children}</span>
    </li>
  );
}

function Pillar({ number, title, body }: { number: string; title: string; body: string }) {
  return (
    <div
      className="rounded-xl p-6"
      style={{
        background: "var(--bg-surface)",
        border: "1px solid var(--border-mid)",
      }}
    >
      <p className="text-xs font-bold uppercase tracking-widest mb-3" style={{ color: "#00c853" }}>
        {number}
      </p>
      <h3 className="text-lg font-bold mb-2" style={{ color: "var(--text-primary)", letterSpacing: "-0.01em" }}>
        {title}
      </h3>
      <p className="text-sm leading-relaxed" style={{ color: "var(--text-secondary)" }}>
        {body}
      </p>
    </div>
  );
}
