"use client";

import { useState } from "react";

interface CertEntry {
  id: string;
  company: string;
  product: string;
  category: string;
  score: number;
  certDate: string;
  expiryDate: string;
  status: "active" | "expiring" | "expired";
  tier: "certified" | "certified-plus" | "enterprise";
}

const REGISTRY: CertEntry[] = [
  {
    id: "AC-2026-001",
    company: "Acme Corp",
    product: "AcmeBot 2.0",
    category: "Customer Support AI",
    score: 87,
    certDate: "2026-01-15",
    expiryDate: "2027-01-15",
    status: "active",
    tier: "certified-plus",
  },
  {
    id: "AC-2026-002",
    company: "Meridian Health",
    product: "ClinicalAssist v3",
    category: "Healthcare AI",
    score: 91,
    certDate: "2026-02-01",
    expiryDate: "2027-02-01",
    status: "active",
    tier: "enterprise",
  },
  {
    id: "AC-2025-019",
    company: "FinCore Systems",
    product: "RiskAdvisor Pro",
    category: "Financial Analysis AI",
    score: 78,
    certDate: "2025-04-10",
    expiryDate: "2026-04-10",
    status: "expiring",
    tier: "certified",
  },
  {
    id: "AC-2026-003",
    company: "Vantage Legal",
    product: "DocReview AI",
    category: "Legal Document AI",
    score: 83,
    certDate: "2026-03-01",
    expiryDate: "2027-03-01",
    status: "active",
    tier: "certified-plus",
  },
];

const TIERS = {
  "certified": {
    label: "AISeal Certified",
    color: "#00c853",
    bg: "rgba(0,200,83,0.1)",
    border: "rgba(0,200,83,0.25)",
    scoreMin: 75,
  },
  "certified-plus": {
    label: "AISeal Certified+",
    color: "#0080ff",
    bg: "rgba(0,128,255,0.1)",
    border: "rgba(0,128,255,0.25)",
    scoreMin: 85,
  },
  "enterprise": {
    label: "AISeal Enterprise",
    color: "#a855f7",
    bg: "rgba(168,85,247,0.1)",
    border: "rgba(168,85,247,0.25)",
    scoreMin: 90,
  },
};

function scoreColor(score: number): string {
  const s = Math.max(0, Math.min(100, score));
  if (s <= 50) {
    const t = s / 50;
    return `rgb(${Math.round(248+(245-248)*t)},${Math.round(81+(158-81)*t)},${Math.round(73+(11-73)*t)})`;
  }
  const t = (s - 50) / 50;
  return `rgb(${Math.round(245+(0-245)*t)},${Math.round(158+(200-158)*t)},${Math.round(11+(83-11)*t)})`;
}

function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
}

function StatusBadge({ status }: { status: CertEntry["status"] }) {
  const styles = {
    active:   { bg: "rgba(0,200,83,0.1)",   color: "#00c853", label: "Active" },
    expiring: { bg: "rgba(245,158,11,0.1)", color: "#f59e0b", label: "Expiring Soon" },
    expired:  { bg: "rgba(248,81,73,0.1)",  color: "#f85149", label: "Expired" },
  };
  const s = styles[status];
  return (
    <span className="inline-flex items-center gap-1.5 text-xs font-medium px-2.5 py-1 rounded-full" style={{ background: s.bg, color: s.color }}>
      <span className="w-1.5 h-1.5 rounded-full" style={{ background: s.color }} />
      {s.label}
    </span>
  );
}

function TierBadge({ tier }: { tier: CertEntry["tier"] }) {
  const t = TIERS[tier];
  return (
    <span className="inline-flex items-center gap-1.5 text-xs font-semibold px-2.5 py-1 rounded-full" style={{ background: t.bg, color: t.color, border: `1px solid ${t.border}` }}>
      <svg width="10" height="10" viewBox="0 0 24 24" fill="none">
        <path d="M12 2L4 6V12C4 16.4 7.4 20.5 12 22C16.6 20.5 20 16.4 20 12V6L12 2Z" stroke="currentColor" strokeWidth="2" strokeLinejoin="round" />
        <path d="M9 12L11 14L15 10" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
      {t.label}
    </span>
  );
}

function CriteriaSection() {
  return (
    <div className="mb-12">
      <p className="text-xs font-semibold uppercase tracking-widest mb-2 text-center" style={{ color: "#00c853" }}>
        Certification Framework
      </p>
      <h2 className="text-2xl font-bold text-center mb-2" style={{ color: "#ededed", letterSpacing: "-0.02em" }}>
        What it takes to get certified
      </h2>
      <p className="text-center text-sm mb-8 max-w-xl mx-auto" style={{ color: "#6b7280" }}>
        AISeal Cert is not a score threshold. It is a criteria-based framework — specific OWASP LLM controls that must be met, verified, and renewed annually.
      </p>

      {/* Mandatory controls */}
      <div className="rounded-xl overflow-hidden mb-4" style={{ border: "1px solid #2a2a2a" }}>
        <div className="px-5 py-3 flex items-center gap-3" style={{ background: "#111111", borderBottom: "1px solid #2a2a2a" }}>
          <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: "#f85149" }} />
          <p className="text-sm font-semibold" style={{ color: "#ededed" }}>Mandatory — All Tiers</p>
          <span className="text-xs ml-auto" style={{ color: "#6b7280" }}>Zero tolerance. Any CRITICAL fail = certification denied.</span>
        </div>
        <div style={{ background: "#0d0d0d" }}>
          {[
            { code: "LLM01", name: "Prompt Injection", reason: "No certification if the AI can be hijacked to override its instructions." },
            { code: "LLM06", name: "Excessive Agency", reason: "No certification if the AI can take unauthorized real-world actions." },
            { code: "LLM07", name: "System Prompt Leakage", reason: "No certification if internal instructions or configuration can be extracted." },
          ].map((c, i, arr) => (
            <div key={c.code} className="px-5 py-4 flex items-start gap-4" style={{ borderBottom: i < arr.length - 1 ? "1px solid #1a1a1a" : "none" }}>
              <span className="text-xs font-mono font-bold flex-shrink-0 mt-0.5" style={{ color: "#f85149" }}>{c.code}</span>
              <div>
                <p className="text-sm font-semibold mb-0.5" style={{ color: "#ededed" }}>{c.name}</p>
                <p className="text-xs" style={{ color: "#6b7280" }}>{c.reason}</p>
              </div>
              <span className="ml-auto flex-shrink-0 text-xs font-bold px-2 py-0.5 rounded" style={{ background: "rgba(248,81,73,0.1)", color: "#f85149" }}>REQUIRED</span>
            </div>
          ))}
        </div>
      </div>

      {/* Conditional controls */}
      <div className="rounded-xl overflow-hidden mb-8" style={{ border: "1px solid #2a2a2a" }}>
        <div className="px-5 py-3 flex items-center gap-3" style={{ background: "#111111", borderBottom: "1px solid #2a2a2a" }}>
          <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: "#f59e0b" }} />
          <p className="text-sm font-semibold" style={{ color: "#ededed" }}>Conditional — Based on Architecture</p>
          <span className="text-xs ml-auto" style={{ color: "#6b7280" }}>Required only if applicable to your deployment.</span>
        </div>
        <div style={{ background: "#0d0d0d" }}>
          {[
            { code: "LLM02", name: "Sensitive Data Disclosure", condition: "Required if handling PII, PHI, or financial data." },
            { code: "LLM04", name: "Data & Model Poisoning", condition: "Required if using retrieval-augmented generation (RAG)." },
            { code: "LLM05", name: "Improper Output Handling", condition: "Required if the AI generates code or executable content." },
          ].map((c, i, arr) => (
            <div key={c.code} className="px-5 py-4 flex items-start gap-4" style={{ borderBottom: i < arr.length - 1 ? "1px solid #1a1a1a" : "none" }}>
              <span className="text-xs font-mono font-bold flex-shrink-0 mt-0.5" style={{ color: "#f59e0b" }}>{c.code}</span>
              <div>
                <p className="text-sm font-semibold mb-0.5" style={{ color: "#ededed" }}>{c.name}</p>
                <p className="text-xs" style={{ color: "#6b7280" }}>{c.condition}</p>
              </div>
              <span className="ml-auto flex-shrink-0 text-xs font-bold px-2 py-0.5 rounded" style={{ background: "rgba(245,158,11,0.1)", color: "#f59e0b" }}>CONDITIONAL</span>
            </div>
          ))}
        </div>
      </div>

      {/* Tier cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {(Object.entries(TIERS) as [keyof typeof TIERS, typeof TIERS[keyof typeof TIERS]][]).map(([key, tier]) => (
          <div key={key} className="rounded-xl p-5" style={{ background: "#111111", border: `1px solid ${tier.border}` }}>
            <TierBadge tier={key} />
            <p className="text-3xl font-bold mt-3 mb-0.5" style={{ color: tier.color }}>{tier.scoreMin}+</p>
            <p className="text-xs mb-3" style={{ color: "#6b7280" }}>Minimum TrustScore</p>
            <ul className="text-xs flex flex-col gap-1.5" style={{ color: "#6b7280" }}>
              <li className="flex gap-2">
                <span style={{ color: tier.color }}>✓</span>
                All mandatory controls pass
              </li>
              {key === "certified" && (
                <li className="flex gap-2"><span style={{ color: tier.color }}>✓</span>No CRITICAL findings</li>
              )}
              {key === "certified-plus" && (<>
                <li className="flex gap-2"><span style={{ color: tier.color }}>✓</span>All applicable conditionals pass</li>
                <li className="flex gap-2"><span style={{ color: tier.color }}>✓</span>No CRITICAL or HIGH findings</li>
              </>)}
              {key === "enterprise" && (<>
                <li className="flex gap-2"><span style={{ color: tier.color }}>✓</span>All mandatory + all conditionals</li>
                <li className="flex gap-2"><span style={{ color: tier.color }}>✓</span>Ghost99RT runtime monitoring</li>
                <li className="flex gap-2"><span style={{ color: tier.color }}>✓</span>Annual audit + SLA</li>
              </>)}
              <li className="flex gap-2"><span style={{ color: tier.color }}>✓</span>Annual renewal required</li>
            </ul>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function RegistryPage() {
  const [search, setSearch] = useState("");

  const filtered = REGISTRY.filter((entry) => {
    const q = search.toLowerCase();
    return !q || entry.company.toLowerCase().includes(q) || entry.product.toLowerCase().includes(q) || entry.category.toLowerCase().includes(q) || entry.id.toLowerCase().includes(q);
  });

  const activeCount = REGISTRY.filter((e) => e.status === "active").length;
  const expiringCount = REGISTRY.filter((e) => e.status === "expiring").length;
  const avgScore = Math.round(REGISTRY.reduce((s, e) => s + e.score, 0) / REGISTRY.length);

  return (
    <div style={{ background: "#0a0a0a", minHeight: "100vh" }}>
      <div className="max-w-5xl mx-auto px-6 py-12">

        {/* Header */}
        <div className="mb-10">
          <p className="text-xs font-semibold uppercase tracking-widest mb-2" style={{ color: "#00c853" }}>AISeal Cert</p>
          <h1 className="text-3xl font-bold mb-2" style={{ color: "#ededed", letterSpacing: "-0.02em" }}>
            AISeal Certified AI Products
          </h1>
          <p className="text-base" style={{ color: "#6b7280" }}>Independently verified. Annually recertified.</p>
        </div>

        {/* Certification criteria */}
        <CriteriaSection />

        {/* Stats */}
        <div className="grid grid-cols-3 gap-4 mb-8">
          <StatCard value={activeCount} label="Active Certifications" color="#00c853" />
          <StatCard value={expiringCount} label="Expiring Soon" color="#f59e0b" />
          <StatCard value={`${avgScore}`} label="Avg TrustScore" color="#0080ff" />
        </div>

        {/* Search */}
        <div className="flex items-center gap-4 mb-6">
          <div className="flex-1 relative">
            <svg className="absolute left-3 top-1/2 -translate-y-1/2" width="16" height="16" viewBox="0 0 24 24" fill="none" style={{ color: "#6b7280" }}>
              <circle cx="11" cy="11" r="7" stroke="currentColor" strokeWidth="1.5" />
              <path d="M20 20L17 17" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
            </svg>
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search by company, product, or category..."
              className="w-full pl-9 pr-4 py-2.5 rounded-lg text-sm outline-none"
              style={{ background: "#111111", border: "1px solid #2a2a2a", color: "#ededed" }}
            />
          </div>
          <a href="/scan" className="flex-shrink-0 px-5 py-2.5 rounded-lg text-sm font-semibold" style={{ background: "#00c853", color: "#000000", textDecoration: "none" }}>
            Apply for Certification
          </a>
        </div>

        {/* Registry table */}
        <div className="rounded-xl overflow-hidden mb-8" style={{ border: "1px solid #2a2a2a" }}>
          <div
            className="grid text-xs font-semibold uppercase tracking-wider px-5 py-3"
            style={{
              background: "#111111", borderBottom: "1px solid #2a2a2a", color: "#6b7280",
              gridTemplateColumns: "90px 1.2fr 1fr 70px 110px 150px",
              gap: "1rem",
            }}
          >
            <span>Cert ID</span>
            <span>Company / Product</span>
            <span>Category</span>
            <span>Score</span>
            <span>Tier</span>
            <span>Status / Expiry</span>
          </div>

          <div style={{ background: "#0d0d0d" }}>
            {filtered.length === 0 ? (
              <div className="px-5 py-12 text-center" style={{ color: "#6b7280" }}>No results match your search.</div>
            ) : (
              filtered.map((entry, i) => (
                <div
                  key={entry.id}
                  className="grid items-center px-5 py-4"
                  style={{
                    borderBottom: i < filtered.length - 1 ? "1px solid #1a1a1a" : "none",
                    gridTemplateColumns: "90px 1.2fr 1fr 70px 110px 150px",
                    gap: "1rem",
                    background: entry.status === "expiring" ? "rgba(245,158,11,0.02)" : "transparent",
                  }}
                >
                  <span className="text-xs font-mono" style={{ color: "#0080ff" }}>{entry.id}</span>

                  <div>
                    <p className="text-sm font-semibold" style={{ color: "#ededed" }}>{entry.product}</p>
                    <p className="text-xs" style={{ color: "#6b7280" }}>{entry.company}</p>
                  </div>

                  <span className="text-sm" style={{ color: "#9ca3af" }}>{entry.category}</span>

                  <span className="text-base font-bold" style={{ color: scoreColor(entry.score) }}>{entry.score}</span>

                  <TierBadge tier={entry.tier} />

                  <div>
                    <StatusBadge status={entry.status} />
                    <p className="text-xs mt-1" style={{ color: "#374151" }}>Expires {formatDate(entry.expiryDate)}</p>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Bottom CTA */}
        <div className="rounded-xl p-6 flex flex-col sm:flex-row items-start sm:items-center gap-6 justify-between" style={{ background: "#111111", border: "1px solid #2a2a2a" }}>
          <div>
            <div className="flex items-center gap-2 mb-2">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none">
                <path d="M12 2L4 6V12C4 16.4 7.4 20.5 12 22C16.6 20.5 20 16.4 20 12V6L12 2Z" fill="rgba(0,200,83,0.15)" stroke="#00c853" strokeWidth="1.5" strokeLinejoin="round" />
                <path d="M9 12L11 14L15 10" stroke="#00c853" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
              <span className="text-xs font-semibold" style={{ color: "#00c853" }}>AISeal Certified</span>
            </div>
            <h3 className="text-lg font-bold mb-1" style={{ color: "#ededed" }}>Get your AI product certified</h3>
            <p className="text-sm" style={{ color: "#6b7280" }}>
              Start with a free TrustScan to see where you stand. AISeal Certification includes a full OWASP LLM Top 10 assessment, a public badge, and annual renewal.
            </p>
          </div>
          <a href="/scan" className="flex-shrink-0 px-5 py-3 rounded-lg text-sm font-semibold whitespace-nowrap" style={{ background: "#0080ff", color: "#ffffff", textDecoration: "none" }}>
            Start with a Free Scan
          </a>
        </div>

      </div>
    </div>
  );
}

function StatCard({ value, label, color }: { value: number | string; label: string; color: string }) {
  return (
    <div className="rounded-xl p-5" style={{ background: "#111111", border: "1px solid #2a2a2a" }}>
      <p className="text-3xl font-bold mb-1" style={{ color }}>{value}</p>
      <p className="text-sm" style={{ color: "#6b7280" }}>{label}</p>
    </div>
  );
}
