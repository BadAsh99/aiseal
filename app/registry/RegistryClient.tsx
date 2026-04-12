"use client";

import { useState, useMemo } from "react";
import Link from "next/link";
import type { CertRecord, CertTier, Industry, Framework } from "../../lib/registry";
import CertBadge from "../components/registry/CertBadge";

interface RegistryClientProps {
  initialCerts: CertRecord[];
}

const TIER_META: Record<CertTier, { label: string; color: string; bg: string; border: string }> = {
  "ACF-1": { label: "ACF-1 Verified", color: "#9ca3af", bg: "rgba(156,163,175,0.1)", border: "rgba(156,163,175,0.25)" },
  "ACF-2": { label: "ACF-2 Assured", color: "#0080ff", bg: "rgba(0,128,255,0.1)", border: "rgba(0,128,255,0.25)" },
  "ACF-3": { label: "ACF-3 Certified", color: "#d4a017", bg: "rgba(212,160,23,0.1)", border: "rgba(212,160,23,0.25)" },
};

const STATUS_META = {
  ACTIVE:       { label: "Active",        color: "#00c853", dot: "#00c853" },
  UNDER_REVIEW: { label: "Under Review",  color: "#f59e0b", dot: "#f59e0b" },
  SUSPENDED:    { label: "Suspended",     color: "#f85149", dot: "#f85149" },
  EXPIRED:      { label: "Expired",       color: "#6b7280", dot: "#6b7280" },
};

const INDUSTRY_LABELS: Record<Industry, string> = {
  healthcare: "Healthcare",
  legal: "Legal",
  fintech: "Fintech",
  "hr-tech": "HR Tech",
  other: "Other",
};

const FRAMEWORK_LABELS: Record<Framework, string> = {
  OWASP: "OWASP LLM Top 10",
  NIST: "NIST AI RMF",
  EU_AI_ACT: "EU AI Act",
  MITRE: "MITRE ATLAS",
};

function scoreColor(s: number): string {
  if (s <= 34) return "#f85149";
  if (s <= 54) return "#fb923c";
  if (s <= 74) return "#f59e0b";
  if (s <= 89) return "#0080ff";
  return "#00c853";
}

function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
}

function VendorCard({ cert }: { cert: CertRecord }) {
  const tier = TIER_META[cert.tier];
  const status = STATUS_META[cert.status];

  return (
    <Link
      href={`/registry/${cert.vendor_id}`}
      style={{ textDecoration: "none" }}
      className="block group"
    >
      <div
        className="rounded-xl p-5 flex flex-col gap-4 transition-all duration-200 h-full"
        style={{
          background: "var(--bg-surface)",
          border: "1px solid var(--border-mid)",
        }}
      >
        {/* Header row */}
        <div className="flex items-start justify-between gap-3">
          <div
            className="w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0 font-bold text-base"
            style={{ background: `${cert.logo_color}20`, color: cert.logo_color, border: `1px solid ${cert.logo_color}30` }}
          >
            {cert.logo_initial}
          </div>
          <span
            className="inline-flex items-center gap-1.5 text-xs font-medium px-2 py-0.5 rounded-full flex-shrink-0"
            style={{ background: `${status.color}15`, color: status.color, border: `1px solid ${status.color}25` }}
          >
            <span className="w-1.5 h-1.5 rounded-full" style={{ background: status.dot }} />
            {status.label}
          </span>
        </div>

        {/* Vendor/Product */}
        <div>
          <p className="font-semibold text-sm mb-0.5" style={{ color: "var(--text-primary)" }}>
            {cert.vendor_name}
          </p>
          <p className="text-sm" style={{ color: "var(--text-muted)" }}>
            {cert.product_name} <span style={{ color: "var(--text-subtle)" }}>{cert.product_version}</span>
          </p>
        </div>

        {/* Industry + Tier */}
        <div className="flex flex-wrap gap-2">
          <span
            className="text-xs px-2 py-0.5 rounded-md font-medium"
            style={{ background: "var(--bg-elevated)", color: "var(--text-secondary)", border: "1px solid var(--border-mid)" }}
          >
            {INDUSTRY_LABELS[cert.industry]}
          </span>
          <span
            className="text-xs px-2 py-0.5 rounded-md font-semibold"
            style={{ background: tier.bg, color: tier.color, border: `1px solid ${tier.border}` }}
          >
            {tier.label}
          </span>
        </div>

        {/* TrustScore */}
        <div className="flex items-center justify-between mt-auto">
          <div>
            <p className="text-xs mb-0.5" style={{ color: "var(--text-muted)" }}>TrustScore</p>
            <p className="text-2xl font-bold" style={{ color: scoreColor(cert.trust_score) }}>
              {cert.trust_score}
            </p>
          </div>
          <div className="text-right">
            <p className="text-xs mb-0.5" style={{ color: "var(--text-muted)" }}>Expires</p>
            <p className="text-xs font-medium" style={{ color: "var(--text-secondary)" }}>
              {formatDate(cert.expiry_date)}
            </p>
          </div>
        </div>

        {/* Cert ID */}
        <div className="pt-3" style={{ borderTop: "1px solid var(--border-subtle)" }}>
          <p className="text-xs font-mono" style={{ color: "#0080ff" }}>{cert.cert_id}</p>
        </div>

        {/* View link */}
        <p className="text-xs font-semibold" style={{ color: "#0080ff" }}>
          View certificate →
        </p>
      </div>
    </Link>
  );
}

export default function RegistryClient({ initialCerts }: RegistryClientProps) {
  const [query, setQuery] = useState("");
  const [tierFilter, setTierFilter] = useState<CertTier | "">("");
  const [industryFilter, setIndustryFilter] = useState<Industry | "">("");
  const [frameworkFilter, setFrameworkFilter] = useState<Framework | "">("");

  const filtered = useMemo(() => {
    return initialCerts.filter((cert) => {
      if (query) {
        const q = query.toLowerCase();
        if (
          !cert.vendor_name.toLowerCase().includes(q) &&
          !cert.product_name.toLowerCase().includes(q) &&
          !cert.cert_id.toLowerCase().includes(q) &&
          !cert.industry.toLowerCase().includes(q)
        ) {
          return false;
        }
      }
      if (tierFilter && cert.tier !== tierFilter) return false;
      if (industryFilter && cert.industry !== industryFilter) return false;
      if (frameworkFilter) {
        const map: Record<Framework, keyof CertRecord["frameworks"]> = {
          OWASP: "owasp",
          NIST: "nist",
          EU_AI_ACT: "euAiAct",
          MITRE: "mitreAtlas",
        };
        if (!cert.frameworks[map[frameworkFilter]]) return false;
      }
      return true;
    });
  }, [initialCerts, query, tierFilter, industryFilter, frameworkFilter]);

  const hasFilters = !!(query || tierFilter || industryFilter || frameworkFilter);

  return (
    <div>
      {/* Search + Filter bar */}
      <div
        className="rounded-xl p-4 mb-8 flex flex-col gap-3"
        style={{ background: "var(--bg-surface)", border: "1px solid var(--border-mid)" }}
      >
        {/* Search */}
        <div className="relative">
          <svg
            className="absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none"
            width="16"
            height="16"
            viewBox="0 0 24 24"
            fill="none"
            style={{ color: "var(--text-muted)" }}
          >
            <circle cx="11" cy="11" r="7" stroke="currentColor" strokeWidth="1.5" />
            <path d="M20 20L17 17" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
          </svg>
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search by vendor, product, cert ID, or industry..."
            className="w-full pl-9 pr-4 py-2.5 rounded-lg text-sm outline-none"
            style={{
              background: "var(--bg-elevated)",
              border: "1px solid var(--border-mid)",
              color: "var(--text-primary)",
            }}
          />
        </div>

        {/* Filter row */}
        <div className="flex flex-wrap gap-2 items-center">
          <span className="text-xs font-medium" style={{ color: "var(--text-muted)" }}>Filter by:</span>

          <select
            value={tierFilter}
            onChange={(e) => setTierFilter(e.target.value as CertTier | "")}
            className="text-xs rounded-md px-2.5 py-1.5 outline-none"
            style={{
              background: tierFilter ? "rgba(0,128,255,0.1)" : "var(--bg-elevated)",
              border: tierFilter ? "1px solid rgba(0,128,255,0.4)" : "1px solid var(--border-mid)",
              color: tierFilter ? "#0080ff" : "var(--text-secondary)",
            }}
          >
            <option value="">All Tiers</option>
            <option value="ACF-1">ACF-1 Verified</option>
            <option value="ACF-2">ACF-2 Assured</option>
            <option value="ACF-3">ACF-3 Certified</option>
          </select>

          <select
            value={industryFilter}
            onChange={(e) => setIndustryFilter(e.target.value as Industry | "")}
            className="text-xs rounded-md px-2.5 py-1.5 outline-none"
            style={{
              background: industryFilter ? "rgba(0,128,255,0.1)" : "var(--bg-elevated)",
              border: industryFilter ? "1px solid rgba(0,128,255,0.4)" : "1px solid var(--border-mid)",
              color: industryFilter ? "#0080ff" : "var(--text-secondary)",
            }}
          >
            <option value="">All Industries</option>
            <option value="healthcare">Healthcare</option>
            <option value="legal">Legal</option>
            <option value="fintech">Fintech</option>
            <option value="hr-tech">HR Tech</option>
            <option value="other">Other</option>
          </select>

          <select
            value={frameworkFilter}
            onChange={(e) => setFrameworkFilter(e.target.value as Framework | "")}
            className="text-xs rounded-md px-2.5 py-1.5 outline-none"
            style={{
              background: frameworkFilter ? "rgba(0,128,255,0.1)" : "var(--bg-elevated)",
              border: frameworkFilter ? "1px solid rgba(0,128,255,0.4)" : "1px solid var(--border-mid)",
              color: frameworkFilter ? "#0080ff" : "var(--text-secondary)",
            }}
          >
            <option value="">All Frameworks</option>
            <option value="OWASP">OWASP LLM Top 10</option>
            <option value="NIST">NIST AI RMF</option>
            <option value="EU_AI_ACT">EU AI Act</option>
            <option value="MITRE">MITRE ATLAS</option>
          </select>

          {hasFilters && (
            <button
              onClick={() => {
                setQuery("");
                setTierFilter("");
                setIndustryFilter("");
                setFrameworkFilter("");
              }}
              className="text-xs px-2.5 py-1.5 rounded-md transition-colors"
              style={{ color: "#f85149", background: "rgba(248,81,73,0.08)", border: "1px solid rgba(248,81,73,0.2)" }}
            >
              Clear filters
            </button>
          )}

          <span className="ml-auto text-xs" style={{ color: "var(--text-muted)" }}>
            {filtered.length} result{filtered.length !== 1 ? "s" : ""}
          </span>
        </div>
      </div>

      {/* Vendor grid */}
      {filtered.length === 0 ? (
        <div
          className="rounded-xl py-20 flex flex-col items-center gap-4"
          style={{ background: "var(--bg-surface)", border: "1px solid var(--border-mid)" }}
        >
          <div
            className="w-14 h-14 rounded-full flex items-center justify-center"
            style={{ background: "rgba(0,128,255,0.08)", border: "1px solid rgba(0,128,255,0.15)" }}
          >
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" style={{ color: "#0080ff" }}>
              <circle cx="11" cy="11" r="7" stroke="currentColor" strokeWidth="1.5" />
              <path d="M20 20L17 17" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
              <path d="M8 11H14M11 8V14" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
            </svg>
          </div>
          <div className="text-center">
            <p className="font-semibold mb-1" style={{ color: "var(--text-primary)" }}>No certifications match</p>
            <p className="text-sm" style={{ color: "var(--text-muted)" }}>
              Try adjusting your filters or search query.
            </p>
          </div>
          <button
            onClick={() => {
              setQuery("");
              setTierFilter("");
              setIndustryFilter("");
              setFrameworkFilter("");
            }}
            className="text-sm px-4 py-2 rounded-md"
            style={{ background: "rgba(0,128,255,0.1)", color: "#0080ff", border: "1px solid rgba(0,128,255,0.25)" }}
          >
            Clear all filters
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {filtered.map((cert) => (
            <VendorCard key={cert.cert_id} cert={cert} />
          ))}
        </div>
      )}
    </div>
  );
}
