/**
 * AISeal Quantum Readiness (QR) Scanner
 *
 * Probes an AI vendor's public endpoint for post-quantum cryptography readiness.
 * Checks: TLS key exchange, certificate signing algorithm, cipher suite.
 * No external dependencies — uses Node.js built-in tls module.
 *
 * NIST PQC standards (FIPS 203/204/205):
 *   ML-KEM (formerly CRYSTALS-Kyber)  — key encapsulation
 *   ML-DSA (formerly CRYSTALS-Dilithium) — digital signatures
 *   SLH-DSA (formerly SPHINCS+)       — digital signatures
 */

import * as tls from "tls";
import * as https from "https";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type QRSeverity = "critical" | "high" | "medium" | "low" | "info";
export type QRStatus = "vulnerable" | "warning" | "quantum-safe" | "unknown";

export interface QRFinding {
  check: string;
  status: QRStatus;
  severity: QRSeverity;
  detail: string;
  current_value: string;
  recommendation: string;
}

export interface QRScanResult {
  scan_id: string;
  target: string;
  hostname: string;
  qs_score: number;         // 0–100, higher = more quantum-safe
  hndl_risk: "critical" | "high" | "medium" | "low"; // Harvest Now Decrypt Later risk
  findings: QRFinding[];
  tls_connected: boolean;
  tls_version: string;
  cipher_suite: string;
  key_exchange: string;
  cert_sig_alg: string;
  cert_subject_cn: string;
  cert_valid_to: string;
  scan_duration_ms: number;
  timestamp: string;
  recommendation_summary: string[];
  nist_pqc_refs: string[];
}

// ---------------------------------------------------------------------------
// Known vulnerable/safe algorithm classifications
// ---------------------------------------------------------------------------

// Key exchange: quantum-vulnerable algorithms (broken by Shor's algorithm)
const VULNERABLE_KEX = new Set([
  "ECDH", "ECDHE", "DHE", "RSA",
  "X25519",      // still ECC — vulnerable to quantum
  "X448",        // still ECC — vulnerable to quantum
  "prime256v1",  // NIST P-256
  "secp384r1",   // NIST P-384
  "secp521r1",   // NIST P-521
]);

// Post-quantum safe key exchange
const SAFE_KEX = new Set([
  "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",   // NIST FIPS 203
  "X25519MLKEM768",                              // Hybrid (transitional safe)
  "P256MLKEM768",
  "MLKEM512", "MLKEM768", "MLKEM1024",
]);

// Certificate signing: quantum-vulnerable
const VULNERABLE_SIG = new Set([
  "RSA-SHA256", "RSA-SHA384", "RSA-SHA512",
  "RSA-SHA1", "RSA-MD5",
  "ECDSA-SHA256", "ECDSA-SHA384", "ECDSA-SHA512",
  "DSA-SHA256",
  "ED25519",   // EdDSA — still ECC family
  "ED448",
]);

// Post-quantum safe signatures
const SAFE_SIG = new Set([
  "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",   // NIST FIPS 204
  "SLH-DSA",                                  // NIST FIPS 205
  "MLDSA44", "MLDSA65", "MLDSA87",
  "FALCON-512", "FALCON-1024",                // NIST round 4 finalist
]);

// High-risk industries for HNDL (Harvest Now Decrypt Later)
const HIGH_RISK_KEYWORDS = [
  "health", "medical", "clinic", "hospital", "pharma",
  "finance", "bank", "invest", "insurance", "payment",
  "defense", "military", "government", "gov", "intel",
  "legal", "law", "court",
  "energy", "critical", "infrastructure",
];

// ---------------------------------------------------------------------------
// Scanner implementation
// ---------------------------------------------------------------------------

interface TLSProbeResult {
  connected: boolean;
  tls_version: string;
  cipher_name: string;
  kex_type: string;
  kex_name: string;
  kex_size: number;
  cert_sig_alg: string;
  cert_subject_cn: string;
  cert_valid_to: string;
  error?: string;
}

function probeTLS(hostname: string, port: number = 443, timeoutMs: number = 10_000): Promise<TLSProbeResult> {
  return new Promise((resolve) => {
    const empty: TLSProbeResult = {
      connected: false,
      tls_version: "unknown",
      cipher_name: "unknown",
      kex_type: "unknown",
      kex_name: "unknown",
      kex_size: 0,
      cert_sig_alg: "unknown",
      cert_subject_cn: "unknown",
      cert_valid_to: "unknown",
    };

    const timer = setTimeout(() => {
      socket.destroy();
      resolve({ ...empty, error: `Connection timed out after ${timeoutMs}ms` });
    }, timeoutMs);

    const socket = tls.connect({ host: hostname, port, rejectUnauthorized: false }, () => {
      clearTimeout(timer);
      try {
        const cipher = socket.getCipher();
        const kexInfo = socket.getEphemeralKeyInfo() as { type?: string; name?: string; size?: number } | null;
        const cert = socket.getPeerCertificate();

        const result: TLSProbeResult = {
          connected: true,
          tls_version: socket.getProtocol() ?? "unknown",
          cipher_name: cipher?.name ?? "unknown",
          kex_type: kexInfo?.type ?? "RSA",   // If no ephemeral key, it's static RSA
          kex_name: kexInfo?.name ?? "RSA",
          kex_size: kexInfo?.size ?? 0,
          cert_sig_alg: (cert as any)?.sigalg ?? "unknown",
          cert_subject_cn: typeof cert?.subject?.CN === "string" ? cert.subject.CN : (typeof cert?.subject?.O === "string" ? cert.subject.O : hostname),
          cert_valid_to: cert?.valid_to ?? "unknown",
        };

        socket.destroy();
        resolve(result);
      } catch (e) {
        socket.destroy();
        resolve({ ...empty, connected: true, error: String(e) });
      }
    });

    socket.on("error", (err) => {
      clearTimeout(timer);
      resolve({ ...empty, error: err.message });
    });
  });
}

function classifyKex(kex_type: string, kex_name: string): { vulnerable: boolean; safe: boolean; label: string } {
  const key = kex_name.toUpperCase();
  const type = kex_type.toUpperCase();

  // Check safe first
  for (const safe of SAFE_KEX) {
    if (key.includes(safe.toUpperCase())) {
      return { vulnerable: false, safe: true, label: kex_name };
    }
  }

  // ECDH/ECDHE = always vulnerable to quantum
  if (type.includes("ECDH") || key.includes("ECDH")) {
    return { vulnerable: true, safe: false, label: `${kex_type}/${kex_name}` };
  }

  // DH = vulnerable
  if (type.includes("DHE") || type.includes("DH")) {
    return { vulnerable: true, safe: false, label: `${kex_type}/${kex_name}` };
  }

  // Static RSA key exchange = vulnerable
  if (type === "RSA" && kex_name === "RSA") {
    return { vulnerable: true, safe: false, label: "RSA (static)" };
  }

  return { vulnerable: false, safe: false, label: kex_name || kex_type };
}

function classifySig(sig_alg: string): { vulnerable: boolean; safe: boolean } {
  const upper = sig_alg.toUpperCase().replace(/\s+/g, "-");

  for (const safe of SAFE_SIG) {
    if (upper.includes(safe.toUpperCase())) return { vulnerable: false, safe: true };
  }
  for (const vuln of VULNERABLE_SIG) {
    if (upper.includes(vuln.toUpperCase())) return { vulnerable: true, safe: false };
  }

  return { vulnerable: false, safe: false };
}

function calcHNDLRisk(hostname: string, domain: string): "critical" | "high" | "medium" | "low" {
  const target = (hostname + domain).toLowerCase();
  const matches = HIGH_RISK_KEYWORDS.filter((k) => target.includes(k));

  if (matches.length >= 3) return "critical";
  if (matches.length >= 2) return "high";
  if (matches.length >= 1) return "medium";
  return "low";
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

export async function runQRScan(targetUrl: string): Promise<QRScanResult> {
  const { randomUUID } = await import("crypto");
  const t0 = Date.now();

  // Parse hostname from URL
  let hostname: string;
  try {
    const u = new URL(targetUrl.startsWith("http") ? targetUrl : `https://${targetUrl}`);
    hostname = u.hostname;
  } catch {
    hostname = targetUrl.replace(/^https?:\/\//, "").split("/")[0];
  }

  const probe = await probeTLS(hostname);
  const findings: QRFinding[] = [];
  let score = 100;

  // --- Check 1: TLS key exchange ---
  const kexClass = classifyKex(probe.kex_type, probe.kex_name);
  if (!probe.connected) {
    findings.push({
      check: "TLS Connectivity",
      status: "unknown",
      severity: "medium",
      detail: `Could not establish TLS connection to ${hostname}:443. ${probe.error ?? ""}`,
      current_value: "unreachable",
      recommendation: "Ensure the endpoint is publicly accessible and has a valid TLS certificate.",
    });
    score -= 20;
  } else if (kexClass.vulnerable) {
    findings.push({
      check: "TLS Key Exchange",
      status: "vulnerable",
      severity: "high",
      detail: `Key exchange uses ${kexClass.label} — quantum-vulnerable. A sufficiently large quantum computer can break this key exchange using Shor's algorithm, enabling retroactive decryption of captured traffic (HNDL attack).`,
      current_value: kexClass.label,
      recommendation: "Migrate to ML-KEM-768 (NIST FIPS 203) key encapsulation. During transition, deploy hybrid X25519MLKEM768.",
    });
    score -= 30;
  } else if (kexClass.safe) {
    findings.push({
      check: "TLS Key Exchange",
      status: "quantum-safe",
      severity: "info",
      detail: `Key exchange uses ${kexClass.label} — post-quantum safe (NIST FIPS 203 ML-KEM family).`,
      current_value: kexClass.label,
      recommendation: "No action required.",
    });
  } else {
    findings.push({
      check: "TLS Key Exchange",
      status: "warning",
      severity: "medium",
      detail: `Key exchange type '${kexClass.label}' — quantum vulnerability status undetermined. May be transitional or non-standard.`,
      current_value: kexClass.label,
      recommendation: "Verify with your TLS library vendor whether this cipher is on the NIST PQC migration path.",
    });
    score -= 10;
  }

  // --- Check 2: Certificate signing algorithm ---
  const sigClass = classifySig(probe.cert_sig_alg);
  if (probe.connected) {
    if (sigClass.vulnerable) {
      findings.push({
        check: "Certificate Signing Algorithm",
        status: "vulnerable",
        severity: "critical",
        detail: `Certificate signed with ${probe.cert_sig_alg} — quantum-vulnerable. Shor's algorithm can forge certificates signed with RSA or ECDSA, enabling man-in-the-middle attacks against authenticated TLS sessions.`,
        current_value: probe.cert_sig_alg,
        recommendation: "Request re-issuance with ML-DSA-65 (NIST FIPS 204) or SLH-DSA signature. DigiCert and Let's Encrypt both have PQC cert programs in public beta.",
      });
      score -= 35;
    } else if (sigClass.safe) {
      findings.push({
        check: "Certificate Signing Algorithm",
        status: "quantum-safe",
        severity: "info",
        detail: `Certificate signed with ${probe.cert_sig_alg} — post-quantum safe.`,
        current_value: probe.cert_sig_alg,
        recommendation: "No action required.",
      });
    } else {
      findings.push({
        check: "Certificate Signing Algorithm",
        status: "warning",
        severity: "medium",
        detail: `Certificate signing algorithm '${probe.cert_sig_alg}' — quantum vulnerability status undetermined.`,
        current_value: probe.cert_sig_alg,
        recommendation: "Confirm signature algorithm with your CA. Standard path: migrate to ML-DSA (FIPS 204).",
      });
      score -= 10;
    }
  }

  // --- Check 3: TLS version ---
  if (probe.connected) {
    const tlsVer = probe.tls_version.toLowerCase();
    if (tlsVer.includes("tlsv1") && !tlsVer.includes("tlsv1.2") && !tlsVer.includes("tlsv1.3")) {
      findings.push({
        check: "TLS Version",
        status: "vulnerable",
        severity: "high",
        detail: `TLS ${probe.tls_version} is deprecated. TLS 1.0/1.1 are blocked by modern browsers and vulnerable to BEAST/POODLE attacks — regardless of quantum risk.`,
        current_value: probe.tls_version,
        recommendation: "Enforce TLS 1.3 minimum. TLS 1.3 is a prerequisite for PQC cipher suite support.",
      });
      score -= 20;
    } else if (tlsVer.includes("tlsv1.2")) {
      findings.push({
        check: "TLS Version",
        status: "warning",
        severity: "low",
        detail: "TLS 1.2 is acceptable but TLS 1.3 is required for native post-quantum cipher suite support. PQC key exchange in TLS 1.2 is experimental.",
        current_value: probe.tls_version,
        recommendation: "Migrate to TLS 1.3 to enable native ML-KEM key encapsulation support.",
      });
      score -= 5;
    } else {
      findings.push({
        check: "TLS Version",
        status: "quantum-safe",
        severity: "info",
        detail: `TLS 1.3 detected — required for post-quantum cipher suite negotiation.`,
        current_value: probe.tls_version,
        recommendation: "No action required. TLS 1.3 supports ML-KEM cipher suites.",
      });
    }
  }

  // --- Check 4: HNDL risk assessment ---
  const hndlRisk = calcHNDLRisk(hostname, targetUrl);
  const hndlSeverityMap: Record<string, QRSeverity> = {
    critical: "critical", high: "high", medium: "medium", low: "info",
  };
  findings.push({
    check: "HNDL Exposure Risk",
    status: hndlRisk === "low" ? "quantum-safe" : (hndlRisk === "medium" ? "warning" : "vulnerable"),
    severity: hndlSeverityMap[hndlRisk] as QRSeverity,
    detail: `Harvest Now Decrypt Later (HNDL) risk assessed as ${hndlRisk.toUpperCase()}. Nation-state adversaries are actively archiving encrypted traffic today to decrypt once quantum computers are available. ${
      hndlRisk !== "low"
        ? "This domain/product appears to handle high-sensitivity data — HNDL risk is elevated."
        : "Standard HNDL risk profile."
    }`,
    current_value: `HNDL risk: ${hndlRisk}`,
    recommendation: hndlRisk === "low"
      ? "Standard PQC migration timeline (NIST target: 2030) applies."
      : "Accelerate PQC migration to TLS 1.3 + ML-KEM. CISA recommends high-risk sectors prioritize by 2027.",
  });
  if (hndlRisk === "critical") score -= 10;
  else if (hndlRisk === "high") score -= 5;

  const finalScore = Math.max(0, Math.min(100, score));

  const recommendations: string[] = [];
  const vulnFindings = findings.filter((f) => f.status === "vulnerable");
  if (vulnFindings.some((f) => f.check === "Certificate Signing Algorithm")) {
    recommendations.push("1. Re-issue certificate with ML-DSA-65 (NIST FIPS 204) — contact DigiCert or Let's Encrypt PQC beta");
  }
  if (vulnFindings.some((f) => f.check === "TLS Key Exchange")) {
    recommendations.push("2. Enable X25519MLKEM768 hybrid key exchange in your TLS config (OpenSSL 3.5+, BoringSSL, AWS-LC)");
  }
  if (findings.some((f) => f.check === "TLS Version" && f.status === "warning")) {
    recommendations.push("3. Force TLS 1.3 minimum — required for ML-KEM cipher suite support");
  }
  if (recommendations.length === 0) {
    recommendations.push("Excellent quantum posture. Continue monitoring NIST FIPS 203/204/205 updates.");
  }

  return {
    scan_id: randomUUID(),
    target: targetUrl,
    hostname,
    qs_score: finalScore,
    hndl_risk: hndlRisk,
    findings,
    tls_connected: probe.connected,
    tls_version: probe.tls_version,
    cipher_suite: probe.cipher_name,
    key_exchange: `${probe.kex_type}/${probe.kex_name}` + (probe.kex_size > 0 ? ` (${probe.kex_size}-bit)` : ""),
    cert_sig_alg: probe.cert_sig_alg,
    cert_subject_cn: probe.cert_subject_cn,
    cert_valid_to: probe.cert_valid_to,
    scan_duration_ms: Date.now() - t0,
    timestamp: new Date().toISOString(),
    recommendation_summary: recommendations,
    nist_pqc_refs: [
      "NIST FIPS 203 — ML-KEM (Key Encapsulation Mechanism)",
      "NIST FIPS 204 — ML-DSA (Module-Lattice Digital Signature)",
      "NIST FIPS 205 — SLH-DSA (Stateless Hash-Based Digital Signature)",
      "CISA PQC Migration Roadmap — https://www.cisa.gov/quantum",
      "NSA CNSA 2.0 Suite — quantum-safe algorithm requirements",
    ],
  };
}
