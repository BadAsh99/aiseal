// AISeal F1+F2 — registry data layer.
// Reads from Supabase `certifications` (RLS-on, anon SELECT allowed by design).
// Replaces the prior hardcoded MOCK_CERTS array. Functions are now async.

import { supabasePublic } from "./supabase/public";

export type CertTier = "ACF-1" | "ACF-2" | "ACF-3";
export type QRTier = "QR-1" | "QR-2";
export type CertStatus = "ACTIVE" | "UNDER_REVIEW" | "SUSPENDED" | "EXPIRED";
export type Industry = "healthcare" | "legal" | "fintech" | "hr-tech" | "other";
export type Framework = "OWASP" | "NIST" | "EU_AI_ACT" | "MITRE";

// QR tier definitions for UI display
export const QR_TIERS: Record<QRTier, { label: string; description: string; color: string }> = {
  "QR-1": {
    label: "QR-1 Inventoried",
    description: "All cryptographic primitives catalogued. PQC migration plan documented and reviewed.",
    color: "#f59e0b",
  },
  "QR-2": {
    label: "QR-2 PQC Ready",
    description: "Fully migrated to post-quantum cryptography. ML-KEM key exchange + ML-DSA/SLH-DSA certificate signing.",
    color: "#00c853",
  },
};

export interface FrameworkCoverage {
  owasp: boolean;
  nist: boolean;
  euAiAct: boolean;
  mitreAtlas: boolean;
}

export interface CertRecord {
  cert_id: string;
  vendor_id: string;
  vendor_name: string;
  /** Domain bound to this cert; used by /api/verify to validate Origin/Referer. null for Pilot vendors. */
  vendor_domain: string | null;
  product_name: string;
  product_version: string;
  industry: Industry;
  tier: CertTier;
  status: CertStatus;
  trust_score: number;
  issued_date: string;
  expiry_date: string;
  frameworks: FrameworkCoverage;
  scope_description: string;
  logo_initial: string;
  logo_color: string;
}

export interface VendorProfile {
  vendor_id: string;
  vendor_name: string;
  website: string;
  description: string;
  certifications: CertRecord[];
}

export interface RegistryStats {
  total_vendors: number;
  total_certifications: number;
  active_certifications: number;
  last_updated: string;
}

// ─── DB row → CertRecord mapping ─────────────────────────────────────────────

interface CertificationsRow {
  cert_id: string;
  vendor_id: string;
  vendor_name: string;
  vendor_domain: string | null;
  product_name: string;
  product_version: string;
  industry: Industry;
  tier: CertTier;
  status: CertStatus;
  trust_score: number;
  issued_date: string;
  expiry_date: string;
  frameworks: FrameworkCoverage;
  scope_description: string;
  logo_initial: string;
  logo_color: string;
}

function rowToCert(r: CertificationsRow): CertRecord {
  return {
    cert_id: r.cert_id,
    vendor_id: r.vendor_id,
    vendor_name: r.vendor_name,
    vendor_domain: r.vendor_domain,
    product_name: r.product_name,
    product_version: r.product_version,
    industry: r.industry,
    tier: r.tier,
    status: r.status,
    trust_score: r.trust_score,
    issued_date: r.issued_date,
    expiry_date: r.expiry_date,
    frameworks: r.frameworks,
    scope_description: r.scope_description,
    logo_initial: r.logo_initial,
    logo_color: r.logo_color,
  };
}

// ─── Query functions (all async now) ─────────────────────────────────────────

export async function getCertified(): Promise<CertRecord[]> {
  const db = supabasePublic();
  const { data, error } = await db
    .from("certifications")
    .select("*")
    .order("issued_date", { ascending: false });
  if (error) {
    // Fail loud — silent empty array masks misconfiguration (today's $0 lesson).
    throw new Error(`registry.getCertified failed: ${error.message}`);
  }
  return (data ?? []).map(rowToCert);
}

export async function getCertByVendorId(vendor_id: string): Promise<CertRecord | null> {
  const db = supabasePublic();
  const { data, error } = await db
    .from("certifications")
    .select("*")
    .eq("vendor_id", vendor_id)
    .maybeSingle();
  if (error) throw new Error(`registry.getCertByVendorId(${vendor_id}) failed: ${error.message}`);
  return data ? rowToCert(data) : null;
}

export async function getCertByCertId(cert_id: string): Promise<CertRecord | null> {
  const db = supabasePublic();
  const { data, error } = await db
    .from("certifications")
    .select("*")
    .eq("cert_id", cert_id)
    .maybeSingle();
  if (error) throw new Error(`registry.getCertByCertId(${cert_id}) failed: ${error.message}`);
  return data ? rowToCert(data) : null;
}

export async function searchRegistry(params: {
  query?: string;
  tier?: CertTier | "";
  industry?: Industry | "";
  framework?: Framework | "";
}): Promise<CertRecord[]> {
  // Filtering happens client-side for simplicity (registry is small during Pilot).
  // Swap to server-side filters once volume grows.
  const all = await getCertified();
  const { query, tier, industry, framework } = params;
  return all.filter((cert) => {
    if (query) {
      const q = query.toLowerCase();
      const match =
        cert.vendor_name.toLowerCase().includes(q) ||
        cert.product_name.toLowerCase().includes(q) ||
        cert.cert_id.toLowerCase().includes(q) ||
        cert.industry.toLowerCase().includes(q);
      if (!match) return false;
    }
    if (tier && cert.tier !== tier) return false;
    if (industry && cert.industry !== industry) return false;
    if (framework) {
      const map: Record<Framework, keyof FrameworkCoverage> = {
        OWASP: "owasp",
        NIST: "nist",
        EU_AI_ACT: "euAiAct",
        MITRE: "mitreAtlas",
      };
      if (!cert.frameworks[map[framework]]) return false;
    }
    return true;
  });
}

export async function getRegistryStats(): Promise<RegistryStats> {
  const certs = await getCertified();
  return {
    total_vendors: new Set(certs.map((c) => c.vendor_id)).size,
    total_certifications: certs.length,
    active_certifications: certs.filter((c) => c.status === "ACTIVE").length,
    last_updated: new Date().toISOString(),
  };
}
