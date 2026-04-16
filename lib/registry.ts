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

const MOCK_CERTS: CertRecord[] = [
  {
    cert_id: "ACF3-2026-0001",
    vendor_id: "meridian-health",
    vendor_name: "Meridian Health Systems",
    product_name: "ClinicalAssist",
    product_version: "v4.2",
    industry: "healthcare",
    tier: "ACF-3",
    status: "ACTIVE",
    trust_score: 94,
    issued_date: "2026-01-10",
    expiry_date: "2027-01-10",
    frameworks: { owasp: true, nist: true, euAiAct: true, mitreAtlas: true },
    scope_description: "RAG-based clinical decision support AI handling PHI. Full OWASP LLM Top 10 assessment covering LLM01–LLM07. NIST AI RMF GOVERN/MAP/MEASURE/MANAGE functions verified. EU AI Act Article 9 risk management documentation reviewed and approved.",
    logo_initial: "M",
    logo_color: "#a855f7",
  },
  {
    cert_id: "ACF2-2026-0002",
    vendor_id: "vantage-legal",
    vendor_name: "Vantage Legal AI",
    product_name: "DocReview Pro",
    product_version: "v2.1",
    industry: "legal",
    tier: "ACF-2",
    status: "ACTIVE",
    trust_score: 88,
    issued_date: "2026-02-14",
    expiry_date: "2027-02-14",
    frameworks: { owasp: true, nist: true, euAiAct: false, mitreAtlas: true },
    scope_description: "Contract analysis and due diligence AI. No PII/PHI handling beyond attorney-client privileged content. All mandatory OWASP controls pass (LLM01, LLM06, LLM07). Sensitive data controls (LLM02) verified. Output handling (LLM05) verified for generated legal summaries.",
    logo_initial: "V",
    logo_color: "#0080ff",
  },
  {
    cert_id: "ACF2-2026-0003",
    vendor_id: "fincore-systems",
    vendor_name: "FinCore Systems",
    product_name: "RiskAdvisor",
    product_version: "v3.0",
    industry: "fintech",
    tier: "ACF-2",
    status: "ACTIVE",
    trust_score: 85,
    issued_date: "2026-03-01",
    expiry_date: "2027-03-01",
    frameworks: { owasp: true, nist: true, euAiAct: true, mitreAtlas: false },
    scope_description: "AI-assisted credit risk scoring and loan decisioning. Handles financial PII. LLM02 (Sensitive Data Disclosure) mandatory for this architecture. NIST AI RMF bias and fairness documentation verified. EU AI Act high-risk AI system classification reviewed.",
    logo_initial: "F",
    logo_color: "#0080ff",
  },
  {
    cert_id: "ACF1-2026-0004",
    vendor_id: "talentiq",
    vendor_name: "TalentIQ",
    product_name: "HireAssist",
    product_version: "v1.4",
    industry: "hr-tech",
    tier: "ACF-1",
    status: "ACTIVE",
    trust_score: 78,
    issued_date: "2026-03-20",
    expiry_date: "2027-03-20",
    frameworks: { owasp: true, nist: false, euAiAct: false, mitreAtlas: false },
    scope_description: "Candidate screening and resume analysis AI. All three mandatory OWASP controls pass (LLM01, LLM06, LLM07). No RAG architecture — LLM04 not applicable. Does not generate executable output — LLM05 not applicable.",
    logo_initial: "T",
    logo_color: "#00c853",
  },
  {
    cert_id: "ACF1-2026-0005",
    vendor_id: "nexus-support",
    vendor_name: "Nexus AI",
    product_name: "SupportGPT",
    product_version: "v2.8",
    industry: "other",
    tier: "ACF-1",
    status: "UNDER_REVIEW",
    trust_score: 76,
    issued_date: "2026-04-01",
    expiry_date: "2027-04-01",
    frameworks: { owasp: true, nist: false, euAiAct: false, mitreAtlas: false },
    scope_description: "Customer support automation AI. All mandatory OWASP controls pass. Currently under scheduled 6-month review audit. Certificate remains valid during review period.",
    logo_initial: "N",
    logo_color: "#f59e0b",
  },
];

export function getCertified(): CertRecord[] {
  return MOCK_CERTS;
}

export function getCertByVendorId(vendor_id: string): CertRecord | null {
  return MOCK_CERTS.find((c) => c.vendor_id === vendor_id) ?? null;
}

export function searchRegistry(params: {
  query?: string;
  tier?: CertTier | "";
  industry?: Industry | "";
  framework?: Framework | "";
}): CertRecord[] {
  const { query, tier, industry, framework } = params;
  return MOCK_CERTS.filter((cert) => {
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

export function getRegistryStats(): RegistryStats {
  const certs = getCertified();
  return {
    total_vendors: new Set(certs.map((c) => c.vendor_id)).size,
    total_certifications: certs.length,
    active_certifications: certs.filter((c) => c.status === "ACTIVE").length,
    last_updated: new Date().toISOString(),
  };
}
