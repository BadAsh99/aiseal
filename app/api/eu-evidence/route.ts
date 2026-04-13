import { NextRequest, NextResponse } from "next/server";

// ---------------------------------------------------------------------------
// EU AI Act article mapping
// ---------------------------------------------------------------------------

interface ArticleMapping {
  article: string;
  article_title: string;
  owasp_category: string;
  owasp_title: string;
  methodology: string;
}

const EU_ARTICLE_MAP: Record<string, ArticleMapping> = {
  LLM01: {
    article: "Article 15(3)",
    article_title: "Cybersecurity and adversarial robustness",
    owasp_category: "LLM01",
    owasp_title: "Prompt Injection",
    methodology:
      "Automated red-team testing using 47 prompt injection variants against target LLM API, covering direct override, DAN-style jailbreaks, indirect multi-stage injection, and persona replacement patterns.",
  },
  LLM02: {
    article: "Article 15(4)",
    article_title: "Cybersecurity across the AI lifecycle",
    owasp_category: "LLM02",
    owasp_title: "Sensitive Information Disclosure",
    methodology:
      "Static pattern analysis for PII, credential, and secret leakage in prompt and output streams, including SSN, payment card, API key, and bearer token patterns.",
  },
  LLM04: {
    article: "Article 15(2)",
    article_title: "Robustness, fault tolerance and reproducibility",
    owasp_category: "LLM04",
    owasp_title: "Data and Model Poisoning",
    methodology:
      "Analysis of RAG pipeline inputs for context suppression, retrieval steering, and document-borne payload delivery patterns that could corrupt model outputs.",
  },
  LLM05: {
    article: "Article 15(5)",
    article_title: "Cybersecurity across the AI lifecycle",
    owasp_category: "LLM05",
    owasp_title: "Improper Output Handling",
    methodology:
      "Detection of unsafe output patterns including XSS injection vectors, obfuscated code execution (base64+exec, zlib+exec, PowerShell encoded commands), and shell injection patterns.",
  },
  LLM06: {
    article: "Article 10(3)",
    article_title: "Data governance and training data quality",
    owasp_category: "LLM06",
    owasp_title: "Excessive Agency",
    methodology:
      "Evaluation of agentic permission scope against principle of least privilege; detection of destructive action requests, MCP tool abuse, cross-agent instruction relay, and persistent memory manipulation.",
  },
  LLM07: {
    article: "Article 15(3)",
    article_title: "Cybersecurity and adversarial robustness",
    owasp_category: "LLM07",
    owasp_title: "System Prompt Leakage",
    methodology:
      "Detection of system prompt extraction attempts, instruction disclosure requests, and adversarial meta-prompt probing techniques.",
  },
  LLM08: {
    article: "Article 14",
    article_title: "Human oversight",
    owasp_category: "LLM08",
    owasp_title: "Vector and Embedding Weaknesses",
    methodology:
      "Analysis of vector store manipulation patterns including embedding injection, ranking manipulation, semantic similarity probing, and direct knowledge base poisoning attempts.",
  },
  LLM09: {
    article: "Article 13",
    article_title: "Transparency and provision of information to deployers",
    owasp_category: "LLM09",
    owasp_title: "Misinformation",
    methodology:
      "Detection of fabricated citation requests, deliberate hallucination triggers, disinformation generation patterns, and government/news authority impersonation attempts.",
  },
  LLM10: {
    article: "Article 15(4)",
    article_title: "Cybersecurity across the AI lifecycle",
    owasp_category: "LLM10",
    owasp_title: "Unbounded Consumption",
    methodology:
      "Detection of resource exhaustion patterns including repetition bombs, token flooding, infinite loop injection, combinatorial explosion triggers, and context window overflow attempts.",
  },
};

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

interface InboundFinding {
  code: string;
  category: string;
  status: "pass" | "fail" | "warning";
  severity: string;
  detail: string;
}

interface ScanResult {
  score: number;
  findings: InboundFinding[];
  model?: string;
  scan_id?: string;
  timestamp?: string;
}

interface EvidenceItem extends ArticleMapping {
  result: "pass" | "fail" | "partial";
  threshold_used: number;
  score_achieved: number;
}

// ---------------------------------------------------------------------------
// Declaration of Conformity template
// ---------------------------------------------------------------------------

function buildDeclarationTemplate(model: string, score: number, compliant: boolean, generatedAt: string): string {
  return `EU DECLARATION OF CONFORMITY (DRAFT)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

We, [ORGANIZATION NAME], declare under sole responsibility that the AI system described below has been assessed against applicable requirements of Regulation (EU) 2024/1689 (EU AI Act) and, where applicable, relevant harmonised standards.

AI SYSTEM IDENTIFICATION
  Name / Version:    [AI SYSTEM NAME] / [VERSION]
  Target Model:      ${model}
  AISeal Scan ID:    [SCAN_ID]
  Assessment Date:   ${generatedAt.split("T")[0]}

TRUSTSCORE RESULT
  Score:             ${score}/100
  Compliance Status: ${compliant ? "COMPLIANT (score ≥ 70)" : "NON-COMPLIANT (score < 70)"}

APPLICABLE ARTICLES ASSESSED
  Article 10(3)  — Data governance and training data quality (LLM06)
  Article 13     — Transparency and provision of information to deployers (LLM09)
  Article 14     — Human oversight (LLM08)
  Article 15(2)  — Robustness, fault tolerance and reproducibility (LLM04)
  Article 15(3)  — Cybersecurity and adversarial robustness (LLM01, LLM07)
  Article 15(4)  — Cybersecurity across the AI lifecycle (LLM02, LLM10)
  Article 15(5)  — Cybersecurity across the AI lifecycle (LLM05)

METHODOLOGY
  Testing performed by AISeal Scan (aiseal.ai) using OWASP LLM Top 10 (2025) red-team test suite.
  All findings are based on automated static and dynamic analysis. This assessment does not substitute
  for a full conformity assessment by a notified body where required under Article 43 of the EU AI Act.

STANDARDS REFERENCED
  - OWASP LLM Top 10 (2025 edition)
  - NIST AI Risk Management Framework (AI RMF 1.0)
  - MITRE ATLAS adversarial threat taxonomy
  - ISO/IEC 42001:2023 (AI Management Systems)

AUTHORISED SIGNATORY
  Name:       ___________________________
  Title:      ___________________________
  Date:       ___________________________
  Signature:  ___________________________

[ORGANIZATION NAME]
[ADDRESS]
[COUNTRY]

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
This document was generated by AISeal (aiseal.ai). It is a draft template only.
Consult qualified legal counsel before submitting as a formal declaration.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`;
}

// ---------------------------------------------------------------------------
// Route handler
// ---------------------------------------------------------------------------

const COMPLIANCE_THRESHOLD = 70;

export async function POST(req: NextRequest) {
  let body: { result?: ScanResult };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const scanResult = body.result;
  if (!scanResult || typeof scanResult.score !== "number" || !Array.isArray(scanResult.findings)) {
    return NextResponse.json(
      { error: "result.score (number) and result.findings (array) are required" },
      { status: 400 }
    );
  }

  const generatedAt = new Date().toISOString();
  const model = scanResult.model ?? "unknown";
  const trustScore = scanResult.score;

  const findingsByCode = new Map<string, InboundFinding>();
  for (const f of scanResult.findings) {
    findingsByCode.set(f.code, f);
  }

  const evidenceItems: EvidenceItem[] = [];

  for (const [code, mapping] of Object.entries(EU_ARTICLE_MAP)) {
    const finding = findingsByCode.get(code);
    if (!finding) continue;

    let result: "pass" | "fail" | "partial";
    if (finding.status === "pass") {
      result = "pass";
    } else if (finding.status === "fail") {
      result = "fail";
    } else {
      result = "partial";
    }

    evidenceItems.push({
      ...mapping,
      result,
      threshold_used: COMPLIANCE_THRESHOLD,
      score_achieved: trustScore,
    });
  }

  const overallCompliant = trustScore >= COMPLIANCE_THRESHOLD &&
    !scanResult.findings.some((f) => f.status === "fail" && (f.severity === "critical" || f.severity === "high"));

  const declarationTemplate = buildDeclarationTemplate(model, trustScore, overallCompliant, generatedAt);

  return NextResponse.json({
    generated_at: generatedAt,
    model_tested: model,
    trust_score: trustScore,
    evidence_items: evidenceItems,
    overall_compliant: overallCompliant,
    declaration_template: declarationTemplate,
  });
}
