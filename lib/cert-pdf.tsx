// AISeal Certificate PDF — procurement-grade artifact.
//
// Rendered server-side via @react-pdf/renderer. One US-Letter page, portrait.
// Embedded HMAC signature + QR code linking to /api/verify/{cert_id} make the
// PDF cryptographically tied to the live registry — anyone with the file can
// scan the QR (or hit the verify URL) and confirm the score + tier on aiseal.ai.

import React from "react";
import { Document, Page, Text, View, Image, StyleSheet } from "@react-pdf/renderer";
import type { CertRecord, CertTier } from "./registry";

interface TierVisual {
  label: string;
  fullName: string;
  color: string;
  bgColor: string;
}

const TIER_VISUAL: Record<CertTier, TierVisual> = {
  "ACF-1": { label: "ACF-1", fullName: "ACF-1 VERIFIED",  color: "#6b7280", bgColor: "#f3f4f6" },
  "ACF-2": { label: "ACF-2", fullName: "ACF-2 ASSURED",   color: "#0057b3", bgColor: "#eff6ff" },
  "ACF-3": { label: "ACF-3", fullName: "ACF-3 CERTIFIED", color: "#8c6a0a", bgColor: "#fef9c3" },
};

const styles = StyleSheet.create({
  page: {
    paddingTop: 36,
    paddingBottom: 32,
    paddingHorizontal: 44,
    fontFamily: "Helvetica",
    color: "#0f172a",
    fontSize: 10,
  },
  // ── Header ─────────────────────────────────────────────────────────────
  headerRow: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    borderBottomWidth: 1.5,
    borderBottomColor: "#0f172a",
    paddingBottom: 12,
    marginBottom: 18,
  },
  brand: {
    fontFamily: "Helvetica-Bold",
    fontSize: 22,
    color: "#0f172a",
    letterSpacing: 0.5,
  },
  brandSub: {
    fontSize: 9,
    color: "#64748b",
    marginTop: 2,
    letterSpacing: 1.4,
    textTransform: "uppercase",
  },
  certIdBlock: {
    alignItems: "flex-end",
  },
  certIdLabel: {
    fontSize: 8,
    color: "#64748b",
    letterSpacing: 1.4,
    textTransform: "uppercase",
  },
  certId: {
    fontFamily: "Courier-Bold",
    fontSize: 14,
    color: "#0f172a",
    marginTop: 2,
  },
  // ── Tier banner ────────────────────────────────────────────────────────
  tierBanner: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "center",
    paddingVertical: 14,
    marginBottom: 18,
    borderWidth: 1.5,
    borderRadius: 6,
  },
  tierBannerText: {
    fontFamily: "Helvetica-Bold",
    fontSize: 18,
    letterSpacing: 4,
  },
  scorePuck: {
    marginLeft: 18,
    paddingHorizontal: 14,
    paddingVertical: 6,
    borderRadius: 4,
    flexDirection: "row",
    alignItems: "baseline",
    gap: 4,
  },
  scoreNum: {
    fontFamily: "Helvetica-Bold",
    fontSize: 22,
  },
  scoreDen: {
    fontSize: 11,
    opacity: 0.8,
  },
  // ── Vendor / Product ───────────────────────────────────────────────────
  vendorName: {
    fontFamily: "Helvetica-Bold",
    fontSize: 26,
    color: "#0f172a",
    letterSpacing: -0.5,
    marginBottom: 2,
  },
  vendorProduct: {
    fontSize: 13,
    color: "#475569",
    marginBottom: 16,
  },
  // ── Details table ──────────────────────────────────────────────────────
  detailsBlock: {
    borderTopWidth: 0.7,
    borderTopColor: "#cbd5e1",
    borderBottomWidth: 0.7,
    borderBottomColor: "#cbd5e1",
    paddingVertical: 4,
    marginBottom: 16,
  },
  detailsRow: {
    flexDirection: "row",
    paddingVertical: 5,
    borderBottomWidth: 0.5,
    borderBottomColor: "#e2e8f0",
  },
  detailsRowLast: {
    flexDirection: "row",
    paddingVertical: 5,
  },
  detailsCol: {
    flex: 1,
    flexDirection: "row",
    justifyContent: "space-between",
    paddingHorizontal: 6,
  },
  detailsLabel: {
    color: "#64748b",
    fontSize: 9,
    letterSpacing: 0.5,
    textTransform: "uppercase",
  },
  detailsValue: {
    fontFamily: "Helvetica-Bold",
    fontSize: 10,
    color: "#0f172a",
    textAlign: "right",
  },
  detailsDivider: {
    width: 0.7,
    backgroundColor: "#cbd5e1",
  },
  // ── Scope ──────────────────────────────────────────────────────────────
  sectionLabel: {
    fontFamily: "Helvetica-Bold",
    fontSize: 9,
    color: "#475569",
    letterSpacing: 1.4,
    textTransform: "uppercase",
    marginBottom: 6,
  },
  scopeText: {
    fontSize: 10.5,
    lineHeight: 1.55,
    color: "#1e293b",
    marginBottom: 16,
  },
  // ── Frameworks ─────────────────────────────────────────────────────────
  fwGrid: {
    flexDirection: "row",
    flexWrap: "wrap",
    marginHorizontal: -3,
    marginBottom: 18,
  },
  fwCell: {
    width: "50%",
    paddingHorizontal: 3,
    marginBottom: 4,
  },
  fwBox: {
    flexDirection: "row",
    alignItems: "center",
    paddingVertical: 6,
    paddingHorizontal: 9,
    borderWidth: 0.7,
    borderRadius: 4,
  },
  fwCheck: {
    width: 12,
    height: 12,
    marginRight: 8,
    alignItems: "center",
    justifyContent: "center",
    borderRadius: 6,
  },
  fwName: {
    fontSize: 10,
    fontFamily: "Helvetica-Bold",
    color: "#0f172a",
  },
  // ── Footer / Verify ────────────────────────────────────────────────────
  verifyRow: {
    flexDirection: "row",
    marginTop: "auto",
    paddingTop: 12,
    borderTopWidth: 1,
    borderTopColor: "#0f172a",
  },
  qr: {
    width: 78,
    height: 78,
    marginRight: 16,
  },
  verifyCol: {
    flex: 1,
    justifyContent: "space-between",
  },
  verifyHead: {
    fontFamily: "Helvetica-Bold",
    fontSize: 11,
    color: "#0f172a",
    marginBottom: 4,
    letterSpacing: 0.5,
  },
  verifySub: {
    fontSize: 9,
    color: "#475569",
    lineHeight: 1.5,
    marginBottom: 4,
  },
  verifyUrl: {
    fontFamily: "Courier",
    fontSize: 8.5,
    color: "#0f172a",
  },
  sigLine: {
    fontFamily: "Courier",
    fontSize: 7.5,
    color: "#475569",
    marginTop: 4,
  },
  footerStripe: {
    marginTop: 10,
    flexDirection: "row",
    justifyContent: "space-between",
    paddingTop: 6,
    borderTopWidth: 0.5,
    borderTopColor: "#cbd5e1",
  },
  footerText: {
    fontSize: 7.5,
    color: "#64748b",
  },
});

function fmt(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleDateString("en-US", { month: "long", day: "numeric", year: "numeric" });
}

function industryLabel(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1).replace("-", " ");
}

interface CertPdfProps {
  cert: CertRecord;
  signature: string;
  qrDataUrl: string;
}

function FrameworkCell({ name, on, color }: { name: string; on: boolean; color: string }) {
  const tint = on ? color : "#94a3b8";
  return (
    <View style={styles.fwCell}>
      <View style={[styles.fwBox, { borderColor: tint, backgroundColor: on ? color + "12" : "#f8fafc" }]}>
        <View style={[styles.fwCheck, { backgroundColor: tint + "30", borderWidth: 0.8, borderColor: tint }]}>
          <Text style={{ fontSize: 8, fontFamily: "Helvetica-Bold", color: tint }}>
            {on ? "✓" : "×"}
          </Text>
        </View>
        <Text style={[styles.fwName, { color: on ? "#0f172a" : "#64748b" }]}>{name}</Text>
      </View>
    </View>
  );
}

export function CertPdf({ cert, signature, qrDataUrl }: CertPdfProps) {
  const tier = TIER_VISUAL[cert.tier];
  const verifyUrl = `https://aiseal.ai/api/verify/${cert.cert_id}`;
  const certUrl = `https://aiseal.ai/registry/${cert.vendor_id}`;

  return (
    <Document
      title={`${cert.vendor_name} — AISeal ${cert.tier} Certificate`}
      author="AISeal"
      subject={`AISeal ${cert.tier} Certification for ${cert.product_name}`}
      keywords={`AISeal, ${cert.tier}, certification, AI trust, ${cert.industry}`}
      creator="AISeal Certificate Authority"
    >
      <Page size="LETTER" style={styles.page}>
        {/* Header */}
        <View style={styles.headerRow}>
          <View>
            <Text style={styles.brand}>AISeal</Text>
            <Text style={styles.brandSub}>AI Certification Authority</Text>
          </View>
          <View style={styles.certIdBlock}>
            <Text style={styles.certIdLabel}>Certificate ID</Text>
            <Text style={styles.certId}>{cert.cert_id}</Text>
          </View>
        </View>

        {/* Tier banner with score puck */}
        <View
          style={[
            styles.tierBanner,
            { borderColor: tier.color, backgroundColor: tier.bgColor },
          ]}
        >
          <Text style={[styles.tierBannerText, { color: tier.color }]}>{tier.fullName}</Text>
          <View style={[styles.scorePuck, { backgroundColor: tier.color }]}>
            <Text style={[styles.scoreNum, { color: "#ffffff" }]}>{cert.trust_score}</Text>
            <Text style={[styles.scoreDen, { color: "#ffffff" }]}>/100</Text>
          </View>
        </View>

        {/* Vendor + product */}
        <Text style={styles.vendorName}>{cert.vendor_name}</Text>
        <Text style={styles.vendorProduct}>
          {cert.product_name} {cert.product_version}
        </Text>

        {/* Details table — 2 columns */}
        <View style={styles.detailsBlock}>
          <View style={styles.detailsRow}>
            <View style={styles.detailsCol}>
              <Text style={styles.detailsLabel}>Tier</Text>
              <Text style={[styles.detailsValue, { color: tier.color }]}>{tier.fullName}</Text>
            </View>
            <View style={styles.detailsDivider} />
            <View style={styles.detailsCol}>
              <Text style={styles.detailsLabel}>TrustScore</Text>
              <Text style={styles.detailsValue}>{cert.trust_score} / 100</Text>
            </View>
          </View>
          <View style={styles.detailsRow}>
            <View style={styles.detailsCol}>
              <Text style={styles.detailsLabel}>Industry</Text>
              <Text style={styles.detailsValue}>{industryLabel(cert.industry)}</Text>
            </View>
            <View style={styles.detailsDivider} />
            <View style={styles.detailsCol}>
              <Text style={styles.detailsLabel}>Status</Text>
              <Text style={styles.detailsValue}>{cert.status.replace("_", " ")}</Text>
            </View>
          </View>
          <View style={styles.detailsRowLast}>
            <View style={styles.detailsCol}>
              <Text style={styles.detailsLabel}>Issued</Text>
              <Text style={styles.detailsValue}>{fmt(cert.issued_date)}</Text>
            </View>
            <View style={styles.detailsDivider} />
            <View style={styles.detailsCol}>
              <Text style={styles.detailsLabel}>Expires</Text>
              <Text style={styles.detailsValue}>{fmt(cert.expiry_date)}</Text>
            </View>
          </View>
        </View>

        {/* Scope */}
        <Text style={styles.sectionLabel}>Certification Scope</Text>
        <Text style={styles.scopeText}>{cert.scope_description}</Text>

        {/* Frameworks Covered */}
        <Text style={styles.sectionLabel}>Frameworks Covered</Text>
        <View style={styles.fwGrid}>
          <FrameworkCell name="OWASP LLM Top 10"  on={cert.frameworks.owasp}      color="#0057b3" />
          <FrameworkCell name="MITRE ATLAS"       on={cert.frameworks.mitreAtlas} color="#0057b3" />
          <FrameworkCell name="NIST AI RMF"       on={cert.frameworks.nist}       color="#0057b3" />
          <FrameworkCell name="EU AI Act"         on={cert.frameworks.euAiAct}    color="#0057b3" />
        </View>

        {/* Verify row pinned to bottom via marginTop: auto */}
        <View style={styles.verifyRow}>
          <Image src={qrDataUrl} style={styles.qr} />
          <View style={styles.verifyCol}>
            <View>
              <Text style={styles.verifyHead}>Independent Verification</Text>
              <Text style={styles.verifySub}>
                Scan the QR code or visit the URL below to verify this certificate against
                the AISeal Verification Registry Service. Verification confirms the tier,
                score, status, and signature shown above match the live registry.
              </Text>
              <Text style={styles.verifyUrl}>{verifyUrl}</Text>
              <Text style={styles.sigLine}>HMAC-SHA256 signature: {signature}</Text>
            </View>
            <View style={styles.footerStripe}>
              <Text style={styles.footerText}>{certUrl}</Text>
              <Text style={styles.footerText}>
                Issued by AISeal · A scanner certifies what it measures. Not legal advice.
              </Text>
            </View>
          </View>
        </View>
      </Page>
    </Document>
  );
}
