"""
AISeal EU AI Act Conformity Evidence Mapper
============================================
Maps AISeal scan results (OWASP LLM Top 10) to EU AI Act article requirements
and generates a structured evidence package + Declaration of Conformity template.

Legal basis:
  - Article 15 requires adversarial testing evidence. The Act does NOT specify
    methodology — automated scanning constitutes evidence when methodology is
    documented and results are tied to probabilistic thresholds (Article 9).
  - AISeal TrustScore (0-100) is the documented probabilistic threshold.

Usage:
  python eu_aiact_mapper.py --scan-results results.json --output evidence.json
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from typing import Any


# ---------------------------------------------------------------------------
# OWASP LLM → EU AI Act article mapping
# ---------------------------------------------------------------------------

ARTICLE_MAPPING: dict[str, dict[str, Any]] = {
    "LLM01": {
        "owasp_name": "Prompt Injection",
        "articles": [
            {
                "ref": "Article 15(3)",
                "title": "Accuracy, Robustness and Cybersecurity",
                "requirement": "High-risk AI systems shall be resilient against attempts by unauthorised "
                               "third parties to alter their use, outputs or performance by exploiting the "
                               "system vulnerabilities, including adversarial inputs designed to make the "
                               "system evade detection.",
                "test_rationale": "Prompt injection attacks directly target model guardrail evasion — "
                                  "the primary adversarial input vector covered by Article 15(3).",
            }
        ],
    },
    "LLM02": {
        "owasp_name": "Sensitive Information Disclosure",
        "articles": [
            {
                "ref": "Article 15(4)",
                "title": "Accuracy, Robustness and Cybersecurity",
                "requirement": "The technical solutions to address AI specific vulnerabilities shall include, "
                               "where appropriate, measures to prevent and control for attacks trying to "
                               "manipulate the training dataset, inputs designed to cause the model to make "
                               "mistakes, or model outputs that expose confidential information.",
                "test_rationale": "LLM02 detects credentials, PII, and sensitive tokens surfaced in prompts "
                                  "or outputs — direct evidence of cybersecurity incident risk under Art 15(4).",
            }
        ],
    },
    "LLM04": {
        "owasp_name": "Model DoS / Data Poisoning",
        "articles": [
            {
                "ref": "Article 15(2)",
                "title": "Accuracy, Robustness and Cybersecurity",
                "requirement": "High-risk AI systems shall be resilient as regards errors, faults or "
                               "inconsistencies that may occur within the system or the environment in which "
                               "the system operates, in particular when interacting with natural persons. "
                               "The technical robustness and accuracy shall account for fault tolerance.",
                "test_rationale": "Denial-of-service and data poisoning attacks directly degrade model "
                                  "robustness and fault tolerance — the core concern of Article 15(2).",
            }
        ],
    },
    "LLM05": {
        "owasp_name": "Supply Chain Vulnerabilities",
        "articles": [
            {
                "ref": "Article 15(5)",
                "title": "Accuracy, Robustness and Cybersecurity",
                "requirement": "Providers of high-risk AI systems shall ensure a level of cybersecurity "
                               "appropriate to the risks. This includes cybersecurity across the full "
                               "lifecycle — development, deployment, and maintenance — including the "
                               "software supply chain.",
                "test_rationale": "LLM05 detects untrusted package sources, unsafe model loading, and "
                                  "shell-execution patterns — all supply chain attack vectors across the lifecycle.",
            }
        ],
    },
    "LLM06": {
        "owasp_name": "Sensitive Data Disclosure / Excessive Agency",
        "articles": [
            {
                "ref": "Article 10(3)",
                "title": "Data and Data Governance",
                "requirement": "Training, validation and testing data sets shall be subject to appropriate "
                               "data governance and management practices. Those practices shall concern "
                               "in particular the collection, storage and further processing of personal "
                               "data in view of applicable Union data protection law.",
                "test_rationale": "LLM06 (in scanner.ts, mapped as Excessive Agency) detects prompts that "
                                  "attempt to exfiltrate or misuse sensitive data at runtime — evidence of "
                                  "data governance risk under Article 10(3).",
            }
        ],
    },
    "LLM07": {
        "owasp_name": "Insecure Plugin Design / System Prompt Leakage",
        "articles": [
            {
                "ref": "Article 15(3)",
                "title": "Accuracy, Robustness and Cybersecurity",
                "requirement": "High-risk AI systems shall be resilient against attempts by unauthorised "
                               "third parties to alter their use, outputs or performance by exploiting "
                               "system vulnerabilities, including adversarial exploitation of plugin "
                               "interfaces and internal instruction surfaces.",
                "test_rationale": "System prompt extraction attacks exploit the plugin/instruction surface "
                                  "to bypass designed constraints — an adversarial exploitation vector "
                                  "directly covered by Article 15(3).",
            }
        ],
    },
    "LLM08": {
        "owasp_name": "Excessive Agency",
        "articles": [
            {
                "ref": "Article 14",
                "title": "Human Oversight",
                "requirement": "High-risk AI systems shall be designed and developed in such a way, "
                               "including with appropriate human-machine interface tools, that they can "
                               "be effectively overseen by natural persons during the period in which the "
                               "AI system is in use. Human oversight measures shall be proportionate to the "
                               "risks and shall aim to minimise the risk of over-reliance.",
                "test_rationale": "Vector/embedding manipulation attacks can cause autonomous AI actions "
                                  "that bypass human oversight — directly relevant to Article 14 requirements "
                                  "for human control of agentic AI behaviour.",
            }
        ],
    },
    "LLM09": {
        "owasp_name": "Overreliance / Misinformation",
        "articles": [
            {
                "ref": "Article 13",
                "title": "Transparency and Provision of Information to Deployers",
                "requirement": "High-risk AI systems shall be designed and developed in such a way as to "
                               "ensure that their operation is sufficiently transparent to enable deployers "
                               "to interpret the system's output and use it appropriately. An appropriate "
                               "type and degree of transparency shall include the system's accuracy "
                               "limitations and foreseeable misuse risks.",
                "test_rationale": "LLM09 detects fabricated citations, misinformation generation, and "
                                  "authority impersonation — failure modes that create overreliance risk "
                                  "and violate the accuracy transparency requirements of Article 13.",
            }
        ],
    },
    "LLM10": {
        "owasp_name": "Model Theft / Unbounded Consumption",
        "articles": [
            {
                "ref": "Article 15(4)",
                "title": "Accuracy, Robustness and Cybersecurity",
                "requirement": "Technical solutions shall include measures to prevent attacks trying to "
                               "manipulate the training dataset, inputs designed to cause the model to "
                               "make mistakes, or model outputs that expose confidential information, "
                               "including model weights and architecture details.",
                "test_rationale": "Unbounded consumption and resource exhaustion attacks degrade model "
                                  "availability and may expose model internals — both classified as "
                                  "cybersecurity risks under Article 15(4).",
            }
        ],
    },
}

# Pass threshold: TrustScore >= 70 satisfies the probabilistic threshold requirement
TRUST_SCORE_THRESHOLD = 70

# Severity → conformity weight (mirrors scanner.ts SEVERITY_MULTIPLIERS)
SEVERITY_CONFORMITY: dict[str, str] = {
    "critical": "non-conformant",
    "high":     "non-conformant",
    "medium":   "partial",
    "low":      "conformant",
    "info":     "conformant",
}


# ---------------------------------------------------------------------------
# Core mapping logic
# ---------------------------------------------------------------------------

def map_findings_to_eu_aiact(scan_results: dict) -> dict:
    """
    Map AISeal scan findings to EU AI Act articles.

    Args:
        scan_results: Raw JSON output from AISeal /api/scan endpoint.

    Returns:
        Dict keyed by OWASP code with article mappings and per-finding verdict.
    """
    findings: list[dict] = scan_results.get("findings", [])
    mapped: dict[str, dict] = {}

    for finding in findings:
        code = finding.get("code", "")
        if code not in ARTICLE_MAPPING:
            continue

        status = finding.get("status", "pass")
        severity = finding.get("severity", "info")
        conformity = _derive_conformity(status, severity)

        mapped[code] = {
            "owasp_code": code,
            "owasp_name": ARTICLE_MAPPING[code]["owasp_name"],
            "scan_status": status,
            "scan_severity": severity,
            "conformity_verdict": conformity,
            "eu_articles": ARTICLE_MAPPING[code]["articles"],
            "detail": finding.get("detail", ""),
            "nist_functions": finding.get("nist", {}).get("functions", []) if finding.get("nist") else [],
            "mitre_ids": [m.get("id") for m in finding.get("mitre", [])] if finding.get("mitre") else [],
        }

    return mapped


def _derive_conformity(status: str, severity: str) -> str:
    """Derive EU AI Act conformity verdict from AISeal finding status and severity."""
    if status == "pass":
        return "conformant"
    if status == "warning":
        return SEVERITY_CONFORMITY.get(severity, "partial")
    # status == "fail"
    return SEVERITY_CONFORMITY.get(severity, "non-conformant")


# ---------------------------------------------------------------------------
# Evidence package generator
# ---------------------------------------------------------------------------

def generate_evidence_package(
    scan_results: dict,
    model_name: str,
    provider: str,
) -> dict:
    """
    Generate a structured EU AI Act conformity evidence package.

    Args:
        scan_results: Raw JSON output from AISeal /api/scan endpoint.
        model_name:   Name of the AI model tested (e.g. "gpt-4o").
        provider:     AI provider name (e.g. "OpenAI").

    Returns:
        Structured evidence package suitable for regulatory submission.
    """
    trust_score: int = scan_results.get("score", 0)
    scan_id: str = scan_results.get("scan_id", "unknown")
    timestamp: str = scan_results.get("timestamp", datetime.now(timezone.utc).isoformat())
    categories_checked: int = scan_results.get("categories_checked", 0)

    mapped_findings = map_findings_to_eu_aiact(scan_results)

    evidence_items = []
    overall_conformant = True

    for code, mapping in mapped_findings.items():
        articles = mapping["eu_articles"]
        conformity = mapping["conformity_verdict"]
        if conformity == "non-conformant":
            overall_conformant = False

        for article in articles:
            evidence_items.append({
                "article_ref": article["ref"],
                "article_title": article["title"],
                "article_requirement_summary": article["requirement"],
                "test_category": f"{code} — {mapping['owasp_name']}",
                "test_methodology": (
                    f"Automated static analysis using AISeal scanner v1.0. "
                    f"Pattern-based adversarial input detection across {categories_checked} OWASP LLM Top 10 "
                    f"categories. Methodology documented at https://aiseal.ai/methodology. "
                    f"Probabilistic threshold: TrustScore >= {TRUST_SCORE_THRESHOLD} (Article 9 basis)."
                ),
                "test_rationale": article["test_rationale"],
                "result": mapping["scan_status"],
                "conformity_verdict": conformity,
                "severity": mapping["scan_severity"],
                "finding_detail": mapping["detail"],
                "trust_score_threshold": TRUST_SCORE_THRESHOLD,
                "trust_score_achieved": trust_score,
                "threshold_met": trust_score >= TRUST_SCORE_THRESHOLD,
                "nist_ai_rmf_functions": mapping["nist_functions"],
                "mitre_atlas_ids": mapping["mitre_ids"],
                "scan_id": scan_id,
                "timestamp": timestamp,
                "model_tested": model_name,
                "provider": provider,
            })

    # Aggregate summary
    verdict_counts: dict[str, int] = {"conformant": 0, "partial": 0, "non-conformant": 0}
    for item in evidence_items:
        verdict_counts[item["conformity_verdict"]] = verdict_counts.get(item["conformity_verdict"], 0) + 1

    overall_verdict = (
        "CONFORMANT" if overall_conformant and trust_score >= TRUST_SCORE_THRESHOLD
        else "NON-CONFORMANT" if not overall_conformant
        else "PARTIAL"
    )

    return {
        "evidence_package_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scan_id": scan_id,
        "model_tested": model_name,
        "provider": provider,
        "scanner": {
            "name": "AISeal",
            "version": "1.0",
            "methodology_url": "https://aiseal.ai/methodology",
            "frameworks_covered": ["OWASP LLM Top 10", "MITRE ATLAS", "NIST AI RMF"],
        },
        "probabilistic_threshold": {
            "basis": "EU AI Act Article 9 — risk management probabilistic thresholds",
            "metric": "AISeal TrustScore",
            "threshold_value": TRUST_SCORE_THRESHOLD,
            "achieved_value": trust_score,
            "threshold_met": trust_score >= TRUST_SCORE_THRESHOLD,
        },
        "overall_verdict": overall_verdict,
        "verdict_summary": verdict_counts,
        "articles_addressed": sorted(
            {item["article_ref"] for item in evidence_items}
        ),
        "evidence_items": evidence_items,
    }


# ---------------------------------------------------------------------------
# Declaration of Conformity template
# ---------------------------------------------------------------------------

def generate_declaration_template(evidence_package: dict) -> str:
    """
    Generate a pre-populated EU Declaration of Conformity template (plain text).

    This document follows the structure required by EU AI Act Annex V
    (Declaration of Conformity for high-risk AI systems).

    Args:
        evidence_package: Output of generate_evidence_package().

    Returns:
        Plain text Declaration of Conformity, ready for legal review and signing.
    """
    ep = evidence_package
    model = ep.get("model_tested", "[MODEL NAME]")
    provider = ep.get("provider", "[PROVIDER]")
    scan_id = ep.get("scan_id", "[SCAN ID]")
    generated_at = ep.get("generated_at", "[DATE]")
    overall_verdict = ep.get("overall_verdict", "[VERDICT]")
    trust_score = ep["probabilistic_threshold"]["achieved_value"]
    threshold = ep["probabilistic_threshold"]["threshold_value"]
    articles = ", ".join(ep.get("articles_addressed", []))
    verdict_summary = ep.get("verdict_summary", {})

    items = ep.get("evidence_items", [])
    findings_block = _format_findings_block(items)

    return f"""================================================================================
EU AI ACT — DECLARATION OF CONFORMITY
Annex V — Regulation (EU) 2024/1689 of the European Parliament and of the Council
================================================================================

This Declaration of Conformity is issued in accordance with Article 47 and
Annex V of Regulation (EU) 2024/1689 on Artificial Intelligence (EU AI Act).

SECTION 1 — SYSTEM IDENTIFICATION
--------------------------------------------------------------------------------
AI System Name          : {model}
Provider / Deployer     : {provider}
System Version          : [VERSION — insert current deployment version]
Intended Purpose        : [PURPOSE — insert intended use per Art. 6 classification]
Risk Classification     : High-Risk AI System (presumed for evidence purposes)
Unique System ID        : {scan_id}

SECTION 2 — DECLARATION
--------------------------------------------------------------------------------
The undersigned hereby declares under sole responsibility that the AI system
identified above has been assessed in accordance with the applicable requirements
of Regulation (EU) 2024/1689, and that the system is in conformity with the
following articles based on the evidence documented herein.

Articles Addressed      : {articles}
Assessment Date         : {generated_at}
Assessment Method       : Automated adversarial testing (AISeal Scanner v1.0)
Methodology Basis       : EU AI Act Article 9 — probabilistic risk thresholds
Methodology Reference   : https://aiseal.ai/methodology

SECTION 3 — PROBABILISTIC THRESHOLD (ARTICLE 9 BASIS)
--------------------------------------------------------------------------------
Metric                  : AISeal TrustScore (0–100 scale)
Documented Threshold    : {threshold} / 100
Achieved Score          : {trust_score} / 100
Threshold Status        : {"MET — score meets or exceeds documented threshold" if trust_score >= threshold else "NOT MET — score is below documented threshold"}

The AISeal TrustScore is a risk-weighted probabilistic metric. Each OWASP LLM
category is assigned a weight reflecting relative threat severity. Findings
trigger severity-weighted deductions from a baseline of 100. The threshold of
{threshold} represents the minimum acceptable adversarial resistance level for
the purposes of this Declaration.

SECTION 4 — EVIDENCE SUMMARY
--------------------------------------------------------------------------------
Total Evidence Items    : {len(items)}
Conformant              : {verdict_summary.get("conformant", 0)}
Partial                 : {verdict_summary.get("partial", 0)}
Non-Conformant          : {verdict_summary.get("non-conformant", 0)}
Overall Verdict         : {overall_verdict}

SECTION 5 — DETAILED EVIDENCE RECORD
--------------------------------------------------------------------------------
{findings_block}

SECTION 6 — RESIDUAL RISKS AND LIMITATIONS
--------------------------------------------------------------------------------
1. This assessment covers static adversarial pattern detection. Dynamic
   runtime testing (live inference under adversarial conditions) is recommended
   as a complement for full Article 15 compliance.

2. AISeal Scanner v1.0 covers OWASP LLM categories LLM01–LLM10. Categories
   not included in this scan version (e.g. agentic ASI01–ASI10) are not
   addressed by this Declaration.

3. This Declaration does not substitute for a full Conformity Assessment under
   Article 43 where a Notified Body is required. Consult legal counsel to
   determine whether self-assessment (Art. 43(2)) or third-party assessment
   applies to your deployment context.

4. TrustScore is a probabilistic threshold, not a guarantee of safety. The
   absence of detected patterns does not rule out novel attack vectors not
   covered by the current pattern library.

SECTION 7 — REFERENCED STANDARDS AND FRAMEWORKS
--------------------------------------------------------------------------------
- OWASP LLM Top 10 (2025 edition)
- MITRE ATLAS v2
- NIST AI RMF 1.0
- ISO/IEC 42001:2023 (AI Management Systems — reference only)
- EU AI Act Regulation (EU) 2024/1689

SECTION 8 — SIGNATORY
--------------------------------------------------------------------------------
Name            : _______________________________________
Title           : _______________________________________
Organisation    : _______________________________________
Date            : _______________________________________
Signature       : _______________________________________

[Authorised representative responsible for this Declaration under Art. 47(1)]

SECTION 9 — DOCUMENT CONTROL
--------------------------------------------------------------------------------
Document ID     : EUAIA-DOC-{scan_id[:8].upper()}
Generated By    : AISeal EU AI Act Mapper v1.0
Generated At    : {generated_at}
Next Review     : [DATE — recommended within 12 months or upon material model change]

================================================================================
END OF DECLARATION
================================================================================
"""


def _format_findings_block(items: list[dict]) -> str:
    """Format evidence items into a readable findings block for the Declaration."""
    if not items:
        return "  No evidence items recorded."

    lines = []
    for i, item in enumerate(items, 1):
        verdict_symbol = {
            "conformant":     "[PASS]",
            "partial":        "[WARN]",
            "non-conformant": "[FAIL]",
        }.get(item["conformity_verdict"], "[?]")

        lines.append(f"  [{i:02d}] {verdict_symbol} {item['article_ref']} — {item['article_title']}")
        lines.append(f"       Test     : {item['test_category']}")
        lines.append(f"       Result   : {item['result'].upper()} / Severity: {item['severity']}")
        lines.append(f"       Verdict  : {item['conformity_verdict'].upper()}")
        lines.append(f"       Detail   : {item['finding_detail'][:120]}{'...' if len(item['finding_detail']) > 120 else ''}")
        if item.get("mitre_atlas_ids"):
            lines.append(f"       MITRE    : {', '.join(item['mitre_atlas_ids'])}")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI wrapper
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Map AISeal scan results to EU AI Act evidence package.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python eu_aiact_mapper.py --scan-results results.json --output evidence.json
  python eu_aiact_mapper.py --scan-results results.json --model gpt-4o --provider OpenAI
  python eu_aiact_mapper.py --scan-results results.json --declaration doc.txt
        """,
    )
    parser.add_argument(
        "--scan-results",
        required=True,
        metavar="FILE",
        help="Path to AISeal scan result JSON (output of /api/scan).",
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        default=None,
        help="Write evidence package JSON to this file (default: stdout).",
    )
    parser.add_argument(
        "--declaration",
        metavar="FILE",
        default=None,
        help="Write Declaration of Conformity plain text to this file.",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="AI model name (overrides value in scan results).",
    )
    parser.add_argument(
        "--provider",
        default="Unknown",
        help="AI provider name (e.g. OpenAI, Anthropic, Azure).",
    )

    args = parser.parse_args()

    # Load scan results
    try:
        with open(args.scan_results, "r", encoding="utf-8") as f:
            scan_results = json.load(f)
    except FileNotFoundError:
        print(f"Error: scan results file not found: {args.scan_results}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: invalid JSON in scan results: {e}", file=sys.stderr)
        sys.exit(1)

    model_name = args.model or scan_results.get("model", "unknown-model")

    # Generate evidence package
    evidence_package = generate_evidence_package(scan_results, model_name, args.provider)

    # Output evidence package
    evidence_json = json.dumps(evidence_package, indent=2)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(evidence_json)
        print(f"Evidence package written to: {args.output}")
    else:
        print(evidence_json)

    # Output declaration
    if args.declaration:
        declaration = generate_declaration_template(evidence_package)
        with open(args.declaration, "w", encoding="utf-8") as f:
            f.write(declaration)
        print(f"Declaration of Conformity written to: {args.declaration}")

    # Print summary to stderr so it shows alongside JSON stdout
    verdict = evidence_package["overall_verdict"]
    score = evidence_package["probabilistic_threshold"]["achieved_value"]
    threshold = evidence_package["probabilistic_threshold"]["threshold_value"]
    print(
        f"\nSummary: {verdict} | TrustScore {score}/{threshold} threshold | "
        f"{len(evidence_package['evidence_items'])} evidence items across "
        f"{len(evidence_package['articles_addressed'])} EU AI Act articles",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
