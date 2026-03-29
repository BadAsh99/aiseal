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
  },
];

function scoreColor(score: number): string {
  if (score >= 70) return "#00c853";
  if (score >= 40) return "#f59e0b";
  return "#f85149";
}

function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
  });
}

function StatusBadge({ status }: { status: CertEntry["status"] }) {
  const styles = {
    active: { bg: "rgba(0,200,83,0.1)", color: "#00c853", label: "Active" },
    expiring: { bg: "rgba(245,158,11,0.1)", color: "#f59e0b", label: "Expiring Soon" },
    expired: { bg: "rgba(248,81,73,0.1)", color: "#f85149", label: "Expired" },
  };
  const s = styles[status];
  return (
    <span
      className="inline-flex items-center gap-1.5 text-xs font-medium px-2.5 py-1 rounded-full"
      style={{ background: s.bg, color: s.color }}
    >
      <span
        className="w-1.5 h-1.5 rounded-full"
        style={{ background: s.color }}
      />
      {s.label}
    </span>
  );
}

function CertBadge() {
  return (
    <div className="flex items-center gap-1.5">
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
        <path
          d="M12 2L4 6V12C4 16.4 7.4 20.5 12 22C16.6 20.5 20 16.4 20 12V6L12 2Z"
          fill="rgba(0,200,83,0.15)"
          stroke="#00c853"
          strokeWidth="1.5"
          strokeLinejoin="round"
        />
        <path
          d="M9 12L11 14L15 10"
          stroke="#00c853"
          strokeWidth="1.5"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
      <span className="text-xs font-semibold" style={{ color: "#00c853" }}>
        AISeal Certified
      </span>
    </div>
  );
}

export default function RegistryPage() {
  const [search, setSearch] = useState("");

  const filtered = REGISTRY.filter((entry) => {
    const q = search.toLowerCase();
    return (
      !q ||
      entry.company.toLowerCase().includes(q) ||
      entry.product.toLowerCase().includes(q) ||
      entry.category.toLowerCase().includes(q) ||
      entry.id.toLowerCase().includes(q)
    );
  });

  const activeCount = REGISTRY.filter((e) => e.status === "active").length;
  const expiringCount = REGISTRY.filter((e) => e.status === "expiring").length;
  const avgScore = Math.round(
    REGISTRY.reduce((s, e) => s + e.score, 0) / REGISTRY.length
  );

  return (
    <div style={{ background: "#0a0a0a", minHeight: "100vh" }}>
      <div className="max-w-5xl mx-auto px-6 py-12">
        {/* Header */}
        <div className="mb-10">
          <p
            className="text-xs font-semibold uppercase tracking-widest mb-2"
            style={{ color: "#00c853" }}
          >
            AISeal Cert
          </p>
          <h1
            className="text-3xl font-bold mb-2"
            style={{ color: "#ededed", letterSpacing: "-0.02em" }}
          >
            AISeal Certified AI Products
          </h1>
          <p className="text-base" style={{ color: "#6b7280" }}>
            Independently verified. Annually recertified.
          </p>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-3 gap-4 mb-8">
          <StatCard value={activeCount} label="Active Certifications" color="#00c853" />
          <StatCard value={expiringCount} label="Expiring Soon" color="#f59e0b" />
          <StatCard value={`${avgScore}`} label="Avg TrustScore" color="#0080ff" />
        </div>

        {/* Search + CTA */}
        <div className="flex items-center gap-4 mb-6">
          <div className="flex-1 relative">
            <svg
              className="absolute left-3 top-1/2 -translate-y-1/2"
              width="16"
              height="16"
              viewBox="0 0 24 24"
              fill="none"
              style={{ color: "#6b7280" }}
            >
              <circle cx="11" cy="11" r="7" stroke="currentColor" strokeWidth="1.5" />
              <path d="M20 20L17 17" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
            </svg>
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search by company, product, or category..."
              className="w-full pl-9 pr-4 py-2.5 rounded-lg text-sm outline-none"
              style={{
                background: "#111111",
                border: "1px solid #2a2a2a",
                color: "#ededed",
              }}
            />
          </div>
          <a
            href="/scan"
            className="flex-shrink-0 px-5 py-2.5 rounded-lg text-sm font-semibold"
            style={{ background: "#00c853", color: "#000000", textDecoration: "none" }}
          >
            Apply for Certification
          </a>
        </div>

        {/* Table */}
        <div
          className="rounded-xl overflow-hidden"
          style={{ border: "1px solid #2a2a2a" }}
        >
          {/* Table header */}
          <div
            className="grid text-xs font-semibold uppercase tracking-wider px-5 py-3"
            style={{
              background: "#111111",
              borderBottom: "1px solid #2a2a2a",
              color: "#6b7280",
              gridTemplateColumns: "1fr 1.2fr 1.2fr 80px 120px 120px 140px",
              gap: "1rem",
            }}
          >
            <span>Cert ID</span>
            <span>Company / Product</span>
            <span>Category</span>
            <span>Score</span>
            <span>Certified</span>
            <span>Expires</span>
            <span>Status</span>
          </div>

          {/* Rows */}
          <div style={{ background: "#0d0d0d" }}>
            {filtered.length === 0 ? (
              <div className="px-5 py-12 text-center" style={{ color: "#6b7280" }}>
                No results match your search.
              </div>
            ) : (
              filtered.map((entry, i) => (
                <div
                  key={entry.id}
                  className="grid items-center px-5 py-4"
                  style={{
                    borderBottom:
                      i < filtered.length - 1 ? "1px solid #1a1a1a" : "none",
                    gridTemplateColumns: "1fr 1.2fr 1.2fr 80px 120px 120px 140px",
                    gap: "1rem",
                    background:
                      entry.status === "expiring"
                        ? "rgba(245,158,11,0.02)"
                        : "transparent",
                  }}
                >
                  <div>
                    <span
                      className="text-xs font-mono"
                      style={{ color: "#0080ff" }}
                    >
                      {entry.id}
                    </span>
                  </div>

                  <div>
                    <p
                      className="text-sm font-semibold"
                      style={{ color: "#ededed" }}
                    >
                      {entry.product}
                    </p>
                    <p className="text-xs" style={{ color: "#6b7280" }}>
                      {entry.company}
                    </p>
                  </div>

                  <div>
                    <span className="text-sm" style={{ color: "#9ca3af" }}>
                      {entry.category}
                    </span>
                  </div>

                  <div>
                    <span
                      className="text-base font-bold"
                      style={{ color: scoreColor(entry.score) }}
                    >
                      {entry.score}
                    </span>
                  </div>

                  <div>
                    <span className="text-sm" style={{ color: "#6b7280" }}>
                      {formatDate(entry.certDate)}
                    </span>
                  </div>

                  <div>
                    <span className="text-sm" style={{ color: "#6b7280" }}>
                      {formatDate(entry.expiryDate)}
                    </span>
                  </div>

                  <div>
                    <StatusBadge status={entry.status} />
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Cert badge section */}
        <div
          className="mt-8 rounded-xl p-6 flex flex-col sm:flex-row items-start sm:items-center gap-6 justify-between"
          style={{ background: "#111111", border: "1px solid #2a2a2a" }}
        >
          <div>
            <CertBadge />
            <h3
              className="text-lg font-bold mt-2 mb-1"
              style={{ color: "#ededed" }}
            >
              Get your AI product certified
            </h3>
            <p className="text-sm" style={{ color: "#6b7280" }}>
              AISeal Certification includes a full OWASP LLM Top 10 assessment, a
              TrustScore, and a public badge for your product page. Annual renewal
              keeps your customers confident.
            </p>
          </div>
          <a
            href="/scan"
            className="flex-shrink-0 px-5 py-3 rounded-lg text-sm font-semibold whitespace-nowrap"
            style={{ background: "#0080ff", color: "#ffffff", textDecoration: "none" }}
          >
            Start Certification
          </a>
        </div>
      </div>
    </div>
  );
}

function StatCard({
  value,
  label,
  color,
}: {
  value: number | string;
  label: string;
  color: string;
}) {
  return (
    <div
      className="rounded-xl p-5"
      style={{
        background: "#111111",
        border: "1px solid #2a2a2a",
      }}
    >
      <p
        className="text-3xl font-bold mb-1"
        style={{ color }}
      >
        {value}
      </p>
      <p className="text-sm" style={{ color: "#6b7280" }}>
        {label}
      </p>
    </div>
  );
}
