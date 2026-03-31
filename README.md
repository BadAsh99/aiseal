# AISeal — AI You Can Trust

**The first AI security trust and certification platform.**
Scan it. Monitor it. Certify it.

🔗 [aiseal.ai](https://aiseal.ai)

---

## What It Is

AISeal is an AI security platform built around the OWASP LLM Top 10. It gives security teams, AI vendors, and enterprise buyers a way to scan, monitor, and certify AI systems against real-world attack vectors — prompt injection, excessive agency, system prompt leakage, RAG poisoning, and more.

Three products. One trust platform.

| Product | What it does |
|---|---|
| **AISeal Scan** | Automated red-team scanning against OWASP LLM Top 10. Get a TrustScore in minutes. |
| **AISeal Monitor** | Runtime LLM surveillance via Ghost99RT. Real-time threat detection, prompt injection alerts, full audit logging. |
| **AISeal Cert** | Third-party AI vendor certification with a public badge and searchable registry. The SOC 2 for AI systems. |

---

## TrustScan

Pattern-based static analysis engine covering all 10 OWASP LLM categories:

| Code | Category | Detection |
|---|---|---|
| LLM01 | Prompt Injection | Direct, soft/social, and multi-stage indirect injection |
| LLM02 | Sensitive Information Disclosure | Credentials, API keys, SSNs, tokens |
| LLM03 | Supply Chain Vulnerabilities | Static analysis (dynamic testing recommended) |
| LLM04 | Data and Model Poisoning | RAG context injection, retrieval manipulation |
| LLM05 | Improper Output Handling | XSS patterns, obfuscated payloads, packed malware patterns |
| LLM06 | Excessive Agency | Destructive commands, MCP tool abuse, multi-agent hijack |
| LLM07 | System Prompt Leakage | System prompt extraction attempts |
| LLM08 | Vector and Embedding Weaknesses | Static analysis (dynamic testing recommended) |
| LLM09 | Misinformation | Static analysis (dynamic testing recommended) |
| LLM10 | Unbounded Consumption | Static analysis (dynamic testing recommended) |

**TrustScore** — 0–100, smooth gradient red→amber→green. Score is a spectrum. Risk label is a judgment call based on findings severity.

**Red Team Suite** — 13 curated test scenarios covering all major attack classes. Run individually or as a full suite with aggregate scoring.

---

## AISeal Cert Framework

Certification is criteria-based, not score-threshold-based.

**Mandatory controls (all tiers):**
- LLM01 Prompt Injection — zero tolerance
- LLM06 Excessive Agency — zero tolerance
- LLM07 System Prompt Leakage — zero tolerance

**Conditional controls (architecture-dependent):**
- LLM02 — required if handling PII, PHI, or financial data
- LLM04 — required if using RAG
- LLM05 — required if generating code or executable content

**Tiers:**

| Tier | Min TrustScore | Requirements |
|---|---|---|
| AISeal Certified | 75+ | All mandatory controls pass, no CRITICAL findings |
| AISeal Certified+ | 85+ | All applicable conditionals pass, no CRITICAL or HIGH |
| AISeal Enterprise | 90+ | All mandatory + all conditionals, Ghost99RT runtime monitoring |

---

## NINE

**Neural Intelligence Node Engine** — the AI security analysis layer built on Ghost99RT.

NINE provides executive risk narratives on TrustScan results and answers follow-up questions about findings in context. It is not a chatbot. It is an intelligence engine — every response is scoped to AI security, OWASP LLM Top 10, and the specific scan results in front of it.

Available on every page via the **N9** floating button.

*Nine nines — 99.9999999% uptime. That's the bar.*

---

## Ghost99RT

Ghost99RT is the runtime engine powering AISeal Monitor. It provides:
- Live LLM traffic surveillance
- Real-time CLEAN / WARN / BLOCK classification
- Prompt injection and threat detection at the proxy layer
- Full audit log with model, latency, and category

The Monitor page is a simulated preview. Production deployment requires Ghost99RT agent installation.

---

## Stack

- **Framework:** Next.js 16 (App Router, TypeScript)
- **Styling:** Tailwind CSS + CSS custom properties (dark/light theme)
- **AI:** Anthropic Claude Sonnet 4.6 (NINE analysis + chat)
- **PDF:** jsPDF (client-side executive summary export)
- **Deploy:** Railway (auto-deploy from GitHub)

---

## Running Locally

```bash
git clone https://github.com/BadAsh99/aiseal.git
cd aiseal
npm install
```

Create `.env.local`:
```
ANTHROPIC_API_KEY=your_key_here
```

```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000)

---

## EU AI Act

AISeal Cert maps directly to EU AI Act Article 9 compliance requirements for high-risk AI systems — documented risk assessments, transparency obligations, and human oversight mechanisms. Enforcement begins August 2026.

---

## License

All rights reserved. © 2026 AISeal — aiseal.ai
