"use client";

import { useState, FormEvent } from "react";
import Link from "next/link";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type Industry = "healthcare" | "legal" | "fintech" | "hr-tech" | "other";
type Tier = "ACF-1" | "ACF-2" | "ACF-3";
type Step = "form" | "submitting" | "success" | "error";

interface FormState {
  company_name: string;
  contact_name: string;
  contact_email: string;
  product_name: string;
  product_version: string;
  website: string;
  industry: Industry | "";
  description: string;
  target_tier: Tier | "";
  frameworks: {
    OWASP: boolean;
    NIST: boolean;
    EU_AI_ACT: boolean;
    MITRE: boolean;
  };
  how_heard: string;
}

const INITIAL: FormState = {
  company_name: "",
  contact_name: "",
  contact_email: "",
  product_name: "",
  product_version: "",
  website: "",
  industry: "",
  description: "",
  target_tier: "",
  frameworks: { OWASP: false, NIST: false, EU_AI_ACT: false, MITRE: false },
  how_heard: "",
};

// ---------------------------------------------------------------------------
// Tier info
// ---------------------------------------------------------------------------

const TIERS: {
  id: Tier;
  label: string;
  badge: string;
  color: string;
  minScore: number;
  desc: string;
  includes: string[];
}[] = [
  {
    id: "ACF-1",
    label: "Verified",
    badge: "ACF-1",
    color: "#9ca3af",
    minScore: 75,
    desc: "Baseline AI safety posture. Mandatory OWASP controls. No CRITICAL findings.",
    includes: ["OWASP LLM Top 10 (mandatory controls)", "TrustScan report", "Public registry listing"],
  },
  {
    id: "ACF-2",
    label: "Assured",
    badge: "ACF-2",
    color: "#0080ff",
    minScore: 85,
    desc: "Full OWASP coverage + NIST AI RMF alignment. No CRITICAL or HIGH findings.",
    includes: ["Everything in ACF-1", "NIST AI RMF verification", "Conditional control assessment", "Annual recertification"],
  },
  {
    id: "ACF-3",
    label: "Certified",
    badge: "ACF-3",
    color: "#d4a017",
    minScore: 90,
    desc: "Full framework coverage including EU AI Act. Runtime monitoring. SLA included.",
    includes: ["Everything in ACF-2", "EU AI Act documentation review", "MITRE ATLAS coverage", "Runtime behavioral monitoring", "SLA + priority support"],
  },
];

// ---------------------------------------------------------------------------
// Component helpers
// ---------------------------------------------------------------------------

function Label({ children, required }: { children: React.ReactNode; required?: boolean }) {
  return (
    <label className="block text-xs font-semibold mb-1.5" style={{ color: "var(--text-secondary)" }}>
      {children}
      {required && <span style={{ color: "#f85149", marginLeft: 4 }}>*</span>}
    </label>
  );
}

function Input({
  value,
  onChange,
  placeholder,
  type = "text",
  disabled,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  type?: string;
  disabled?: boolean;
}) {
  return (
    <input
      type={type}
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder}
      disabled={disabled}
      className="w-full px-3 py-2.5 rounded-lg text-sm outline-none transition-colors"
      style={{
        background: "var(--bg-elevated)",
        border: "1px solid var(--border-mid)",
        color: "var(--text-primary)",
        opacity: disabled ? 0.5 : 1,
      }}
      onFocus={(e) => (e.target.style.borderColor = "#0080ff")}
      onBlur={(e) => (e.target.style.borderColor = "var(--border-mid)")}
    />
  );
}

function Textarea({
  value,
  onChange,
  placeholder,
  rows = 4,
  disabled,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  rows?: number;
  disabled?: boolean;
}) {
  return (
    <textarea
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder}
      rows={rows}
      disabled={disabled}
      className="w-full px-3 py-2.5 rounded-lg text-sm outline-none resize-none transition-colors"
      style={{
        background: "var(--bg-elevated)",
        border: "1px solid var(--border-mid)",
        color: "var(--text-primary)",
        opacity: disabled ? 0.5 : 1,
        lineHeight: "1.6",
      }}
      onFocus={(e) => (e.target.style.borderColor = "#0080ff")}
      onBlur={(e) => (e.target.style.borderColor = "var(--border-mid)")}
    />
  );
}

function Select({
  value,
  onChange,
  children,
  disabled,
}: {
  value: string;
  onChange: (v: string) => void;
  children: React.ReactNode;
  disabled?: boolean;
}) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      disabled={disabled}
      className="w-full px-3 py-2.5 rounded-lg text-sm outline-none"
      style={{
        background: "var(--bg-elevated)",
        border: "1px solid var(--border-mid)",
        color: value ? "var(--text-primary)" : "var(--text-muted)",
        opacity: disabled ? 0.5 : 1,
        appearance: "auto",
      }}
    >
      {children}
    </select>
  );
}

function SectionHeader({ number, title, subtitle }: { number: string; title: string; subtitle: string }) {
  return (
    <div className="flex items-start gap-4 mb-6">
      <div
        className="w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold flex-shrink-0 mt-0.5"
        style={{ background: "rgba(0,128,255,0.1)", color: "#0080ff", border: "1px solid rgba(0,128,255,0.25)" }}
      >
        {number}
      </div>
      <div>
        <h2 className="font-bold text-base" style={{ color: "var(--text-primary)" }}>{title}</h2>
        <p className="text-xs mt-0.5" style={{ color: "var(--text-muted)" }}>{subtitle}</p>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main form
// ---------------------------------------------------------------------------

export default function RegistryApplyPage() {
  const [form, setForm] = useState<FormState>(INITIAL);
  const [step, setStep] = useState<Step>("form");
  const [applicationId, setApplicationId] = useState<string>("");
  const [errorMsg, setErrorMsg] = useState<string>("");

  function set<K extends keyof FormState>(key: K, value: FormState[K]) {
    setForm((prev) => ({ ...prev, [key]: value }));
  }

  function toggleFramework(key: keyof FormState["frameworks"]) {
    setForm((prev) => ({
      ...prev,
      frameworks: { ...prev.frameworks, [key]: !prev.frameworks[key] },
    }));
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setStep("submitting");
    setErrorMsg("");

    const frameworks = (Object.keys(form.frameworks) as (keyof FormState["frameworks"])[])
      .filter((k) => form.frameworks[k]);

    const payload = {
      company_name: form.company_name,
      contact_name: form.contact_name,
      contact_email: form.contact_email,
      product_name: form.product_name,
      product_version: form.product_version,
      website: form.website,
      industry: form.industry,
      description: form.description,
      target_tier: form.target_tier,
      frameworks,
      how_heard: form.how_heard,
    };

    try {
      const res = await fetch("/api/registry/apply", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      const data = await res.json();

      if (!res.ok) {
        setErrorMsg(data.error ?? "Submission failed. Please try again.");
        setStep("error");
        return;
      }

      setApplicationId(data.application_id);
      setStep("success");
    } catch {
      setErrorMsg("Network error. Please check your connection and try again.");
      setStep("error");
    }
  }

  const isDisabled = step === "submitting";

  // ──────────────────────────────────────────────────────────────
  // SUCCESS STATE
  // ──────────────────────────────────────────────────────────────
  if (step === "success") {
    return (
      <div
        style={{ background: "var(--bg-base)", minHeight: "100vh" }}
        className="flex items-center justify-center px-6 py-24"
      >
        <div className="max-w-lg w-full text-center">
          <div
            className="w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-6"
            style={{ background: "rgba(0,200,83,0.1)", border: "1px solid rgba(0,200,83,0.25)" }}
          >
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none">
              <path d="M12 2L4 6V12C4 16.4 7.4 20.5 12 22C16.6 20.5 20 16.4 20 12V6L12 2Z"
                fill="rgba(0,200,83,0.15)" stroke="#00c853" strokeWidth="1.5" strokeLinejoin="round" />
              <path d="M9 12L11 14L15 10" stroke="#00c853" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </div>

          <h1 className="text-2xl font-bold mb-3" style={{ color: "var(--text-primary)", letterSpacing: "-0.02em" }}>
            Application Received
          </h1>
          <p className="text-sm mb-6 leading-relaxed" style={{ color: "var(--text-secondary)" }}>
            Your certification application is in the queue. We&apos;ll review it and reach out
            to <strong style={{ color: "var(--text-primary)" }}>{form.contact_email}</strong> within
            5 business days.
          </p>

          <div
            className="rounded-xl p-5 mb-8 text-left"
            style={{ background: "var(--bg-surface)", border: "1px solid var(--border-mid)" }}
          >
            <p className="text-xs font-semibold uppercase tracking-widest mb-1" style={{ color: "var(--text-muted)" }}>
              Application ID
            </p>
            <p className="text-xl font-bold font-mono" style={{ color: "#00c853" }}>{applicationId}</p>
            <p className="text-xs mt-2" style={{ color: "var(--text-muted)" }}>
              Keep this ID for your records. Reference it in any correspondence with AISeal.
            </p>
          </div>

          <div className="flex gap-3 justify-center flex-wrap">
            <Link
              href="/registry"
              className="px-5 py-2.5 rounded-md text-sm font-semibold"
              style={{ background: "#00c853", color: "#000", textDecoration: "none" }}
            >
              Browse the Registry
            </Link>
            <Link
              href="/scan"
              className="px-5 py-2.5 rounded-md text-sm font-semibold"
              style={{
                background: "transparent",
                color: "var(--text-primary)",
                border: "1px solid var(--border-mid)",
                textDecoration: "none",
              }}
            >
              Run a TrustScan
            </Link>
          </div>
        </div>
      </div>
    );
  }

  // ──────────────────────────────────────────────────────────────
  // FORM STATE (+ error inline)
  // ──────────────────────────────────────────────────────────────
  return (
    <div style={{ background: "var(--bg-base)", minHeight: "100vh" }}>
      {/* Hero */}
      <section
        className="text-center px-6 py-16"
        style={{
          background: "radial-gradient(ellipse 60% 35% at 50% -5%, rgba(0,200,83,0.08) 0%, transparent 65%)",
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
          Private Pilot Program — Limited Spots
        </div>

        <h1
          className="text-4xl font-bold mb-3"
          style={{ color: "var(--text-primary)", letterSpacing: "-0.03em", lineHeight: "1.1" }}
        >
          Apply for
          <br />
          <span style={{ color: "#00c853" }}>AISeal Certification</span>
        </h1>

        <p className="text-base max-w-md mx-auto" style={{ color: "var(--text-secondary)", lineHeight: "1.6" }}>
          Join the first independent AI certification registry. Get publicly verified against
          OWASP LLM Top 10, NIST AI RMF, and EU AI Act standards.
        </p>
      </section>

      {/* Content */}
      <div className="max-w-5xl mx-auto px-6 py-12 grid grid-cols-1 lg:grid-cols-3 gap-10">
        {/* Sidebar */}
        <aside className="lg:col-span-1 flex flex-col gap-4">
          <p className="text-xs font-semibold uppercase tracking-widest mb-2" style={{ color: "var(--text-muted)" }}>
            Certification Tiers
          </p>
          {TIERS.map((tier) => (
            <div
              key={tier.id}
              className="rounded-xl p-4 flex flex-col gap-2 cursor-pointer transition-all"
              onClick={() => set("target_tier", tier.id)}
              style={{
                background: form.target_tier === tier.id ? `${tier.color}10` : "var(--bg-surface)",
                border: form.target_tier === tier.id
                  ? `1px solid ${tier.color}50`
                  : "1px solid var(--border-mid)",
              }}
            >
              <div className="flex items-center justify-between">
                <span
                  className="text-xs font-bold px-2 py-0.5 rounded-md"
                  style={{ background: `${tier.color}15`, color: tier.color, border: `1px solid ${tier.color}30` }}
                >
                  {tier.badge}
                </span>
                <span className="text-xs font-semibold" style={{ color: tier.color }}>
                  {tier.minScore}+ score
                </span>
              </div>
              <p className="font-semibold text-sm" style={{ color: "var(--text-primary)" }}>{tier.label}</p>
              <p className="text-xs leading-relaxed" style={{ color: "var(--text-muted)" }}>{tier.desc}</p>
              <ul className="mt-1 flex flex-col gap-1">
                {tier.includes.map((item) => (
                  <li key={item} className="flex items-start gap-1.5 text-xs" style={{ color: "var(--text-muted)" }}>
                    <span style={{ color: tier.color, flexShrink: 0 }}>✓</span>
                    {item}
                  </li>
                ))}
              </ul>
            </div>
          ))}

          <div
            className="rounded-xl p-4 mt-2"
            style={{ background: "rgba(0,128,255,0.04)", border: "1px solid rgba(0,128,255,0.15)" }}
          >
            <p className="text-xs font-semibold mb-2" style={{ color: "#0080ff" }}>Not sure which tier?</p>
            <p className="text-xs leading-relaxed" style={{ color: "var(--text-muted)" }}>
              Start with a free TrustScan. We&apos;ll score your AI and recommend the right tier
              based on the results before you commit.
            </p>
            <Link
              href="/scan"
              className="inline-block mt-3 text-xs font-semibold"
              style={{ color: "#0080ff", textDecoration: "none" }}
            >
              Run a free scan →
            </Link>
          </div>
        </aside>

        {/* Form */}
        <main className="lg:col-span-2">
          <form onSubmit={handleSubmit} className="flex flex-col gap-8">
            {/* Error banner */}
            {step === "error" && (
              <div
                className="rounded-lg px-4 py-3 text-sm flex items-start gap-3"
                style={{ background: "rgba(248,81,73,0.08)", border: "1px solid rgba(248,81,73,0.25)", color: "#f85149" }}
              >
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" className="flex-shrink-0 mt-0.5">
                  <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="1.5" />
                  <path d="M12 8V12M12 16H12.01" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
                </svg>
                {errorMsg}
              </div>
            )}

            {/* Section 1: Company */}
            <div
              className="rounded-xl p-6"
              style={{ background: "var(--bg-surface)", border: "1px solid var(--border-mid)" }}
            >
              <SectionHeader
                number="1"
                title="Company Information"
                subtitle="Who is applying for certification?"
              />
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="sm:col-span-2">
                  <Label required>Company Name</Label>
                  <Input
                    value={form.company_name}
                    onChange={(v) => set("company_name", v)}
                    placeholder="Acme AI, Inc."
                    disabled={isDisabled}
                  />
                </div>
                <div>
                  <Label required>Your Name</Label>
                  <Input
                    value={form.contact_name}
                    onChange={(v) => set("contact_name", v)}
                    placeholder="Jane Smith"
                    disabled={isDisabled}
                  />
                </div>
                <div>
                  <Label required>Work Email</Label>
                  <Input
                    type="email"
                    value={form.contact_email}
                    onChange={(v) => set("contact_email", v)}
                    placeholder="jane@acmeai.com"
                    disabled={isDisabled}
                  />
                </div>
                <div className="sm:col-span-2">
                  <Label>Company Website</Label>
                  <Input
                    value={form.website}
                    onChange={(v) => set("website", v)}
                    placeholder="https://acmeai.com"
                    disabled={isDisabled}
                  />
                </div>
              </div>
            </div>

            {/* Section 2: Product */}
            <div
              className="rounded-xl p-6"
              style={{ background: "var(--bg-surface)", border: "1px solid var(--border-mid)" }}
            >
              <SectionHeader
                number="2"
                title="Product Information"
                subtitle="What AI system do you want certified?"
              />
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <Label required>Product Name</Label>
                  <Input
                    value={form.product_name}
                    onChange={(v) => set("product_name", v)}
                    placeholder="AcmeAssist"
                    disabled={isDisabled}
                  />
                </div>
                <div>
                  <Label>Version</Label>
                  <Input
                    value={form.product_version}
                    onChange={(v) => set("product_version", v)}
                    placeholder="v2.4"
                    disabled={isDisabled}
                  />
                </div>
                <div className="sm:col-span-2">
                  <Label required>Industry</Label>
                  <Select
                    value={form.industry}
                    onChange={(v) => set("industry", v as Industry)}
                    disabled={isDisabled}
                  >
                    <option value="">Select industry…</option>
                    <option value="healthcare">Healthcare</option>
                    <option value="legal">Legal</option>
                    <option value="fintech">Fintech</option>
                    <option value="hr-tech">HR Tech</option>
                    <option value="other">Other</option>
                  </Select>
                </div>
                <div className="sm:col-span-2">
                  <Label required>Describe your AI system</Label>
                  <Textarea
                    value={form.description}
                    onChange={(v) => set("description", v)}
                    placeholder="Briefly describe what your AI does, who uses it, what data it processes, and any known security controls already in place. The more context, the faster the assessment."
                    rows={5}
                    disabled={isDisabled}
                  />
                  <p className="text-xs mt-1.5" style={{ color: "var(--text-muted)" }}>
                    {form.description.length}/2000 characters
                  </p>
                </div>
              </div>
            </div>

            {/* Section 3: Certification Goals */}
            <div
              className="rounded-xl p-6"
              style={{ background: "var(--bg-surface)", border: "1px solid var(--border-mid)" }}
            >
              <SectionHeader
                number="3"
                title="Certification Goals"
                subtitle="What are you applying for? (Click a tier in the sidebar to pre-select)"
              />
              <div className="flex flex-col gap-5">
                {/* Tier selector */}
                <div>
                  <Label required>Target Certification Tier</Label>
                  <div className="grid grid-cols-3 gap-3 mt-2">
                    {TIERS.map((tier) => (
                      <button
                        key={tier.id}
                        type="button"
                        onClick={() => set("target_tier", tier.id)}
                        disabled={isDisabled}
                        className="rounded-lg p-3 text-left transition-all"
                        style={{
                          background: form.target_tier === tier.id ? `${tier.color}12` : "var(--bg-elevated)",
                          border: form.target_tier === tier.id
                            ? `2px solid ${tier.color}`
                            : "2px solid var(--border-mid)",
                        }}
                      >
                        <p className="text-xs font-bold" style={{ color: tier.color }}>{tier.badge}</p>
                        <p className="text-xs font-semibold mt-0.5" style={{ color: "var(--text-primary)" }}>
                          {tier.label}
                        </p>
                      </button>
                    ))}
                  </div>
                </div>

                {/* Frameworks */}
                <div>
                  <Label>Frameworks to Assess</Label>
                  <p className="text-xs mb-3" style={{ color: "var(--text-muted)" }}>
                    OWASP LLM Top 10 is assessed for all tiers. Select any additional frameworks.
                  </p>
                  <div className="grid grid-cols-2 gap-2">
                    {([
                      { key: "OWASP" as const, label: "OWASP LLM Top 10", required: true },
                      { key: "NIST" as const, label: "NIST AI RMF", required: false },
                      { key: "EU_AI_ACT" as const, label: "EU AI Act", required: false },
                      { key: "MITRE" as const, label: "MITRE ATLAS", required: false },
                    ]).map(({ key, label, required: req }) => (
                      <label
                        key={key}
                        className="flex items-center gap-2.5 cursor-pointer rounded-lg px-3 py-2.5 select-none transition-colors"
                        style={{
                          background: (form.frameworks[key] || req)
                            ? "rgba(0,128,255,0.06)"
                            : "var(--bg-elevated)",
                          border: (form.frameworks[key] || req)
                            ? "1px solid rgba(0,128,255,0.3)"
                            : "1px solid var(--border-mid)",
                        }}
                      >
                        <input
                          type="checkbox"
                          checked={form.frameworks[key] || !!req}
                          onChange={() => !req && toggleFramework(key)}
                          disabled={isDisabled || !!req}
                          className="w-3.5 h-3.5 rounded accent-blue-500"
                        />
                        <span className="text-xs font-medium" style={{ color: "var(--text-secondary)" }}>
                          {label}
                          {req && <span className="ml-1.5 text-xs" style={{ color: "var(--text-muted)" }}>(always)</span>}
                        </span>
                      </label>
                    ))}
                  </div>
                </div>

                {/* How did you hear */}
                <div>
                  <Label>How did you find out about AISeal?</Label>
                  <Select
                    value={form.how_heard}
                    onChange={(v) => set("how_heard", v)}
                    disabled={isDisabled}
                  >
                    <option value="">Select…</option>
                    <option value="linkedin">LinkedIn</option>
                    <option value="google">Google / Search</option>
                    <option value="colleague">Colleague or peer</option>
                    <option value="paloalto">Palo Alto Networks</option>
                    <option value="conference">Conference / Event</option>
                    <option value="press">Press / Publication</option>
                    <option value="other">Other</option>
                  </Select>
                </div>
              </div>
            </div>

            {/* Submit */}
            <div className="flex items-center justify-between gap-4">
              <p className="text-xs" style={{ color: "var(--text-muted)" }}>
                By submitting, you agree to be contacted by the AISeal team regarding your application.
                No commitment required.
              </p>
              <button
                type="submit"
                disabled={isDisabled || !form.company_name || !form.contact_email || !form.product_name || !form.industry || !form.description || !form.target_tier}
                className="flex-shrink-0 px-6 py-3 rounded-md text-sm font-semibold flex items-center gap-2 transition-all"
                style={{
                  background: "#00c853",
                  color: "#000",
                  opacity: (isDisabled || !form.company_name || !form.contact_email || !form.product_name || !form.industry || !form.description || !form.target_tier) ? 0.45 : 1,
                  cursor: (isDisabled || !form.company_name || !form.contact_email || !form.product_name || !form.industry || !form.description || !form.target_tier) ? "not-allowed" : "pointer",
                }}
              >
                {step === "submitting" ? (
                  <>
                    <svg className="animate-spin" width="14" height="14" viewBox="0 0 24 24" fill="none">
                      <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="2" strokeDasharray="28" strokeDashoffset="10" />
                    </svg>
                    Submitting…
                  </>
                ) : (
                  "Submit Application"
                )}
              </button>
            </div>
          </form>
        </main>
      </div>
    </div>
  );
}
