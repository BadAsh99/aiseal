"""
AISeal TrustScan Engine — ported from Next.js route.ts
Pattern logic is the single source of truth. Next.js proxies here.
"""

import re
from models import Finding, NistMapping, MitreMapping

NIST_MAPPINGS = {
    "LLM01": NistMapping(functions=["MEASURE", "MANAGE"],  pillars=["Secure & Resilient", "Accountable & Transparent"]),
    "LLM02": NistMapping(functions=["MAP", "MANAGE"],      pillars=["Privacy-Enhanced", "Accountable & Transparent"]),
    "LLM03": NistMapping(functions=["GOVERN", "MAP"],      pillars=["Secure & Resilient", "Valid & Reliable"]),
    "LLM04": NistMapping(functions=["MAP", "MEASURE"],     pillars=["Valid & Reliable", "Secure & Resilient"]),
    "LLM05": NistMapping(functions=["MEASURE", "MANAGE"],  pillars=["Safe", "Secure & Resilient"]),
    "LLM06": NistMapping(functions=["GOVERN", "MANAGE"],   pillars=["Accountable & Transparent", "Safe"]),
    "LLM07": NistMapping(functions=["MEASURE", "MANAGE"],  pillars=["Secure & Resilient", "Privacy-Enhanced"]),
    "LLM08": NistMapping(functions=["MAP", "MEASURE"],     pillars=["Valid & Reliable", "Secure & Resilient"]),
    "LLM09": NistMapping(functions=["MAP", "MEASURE"],     pillars=["Valid & Reliable", "Accountable & Transparent"]),
    "LLM10": NistMapping(functions=["GOVERN", "MANAGE"],   pillars=["Secure & Resilient", "Safe"]),
}

# MITRE ATLAS v5.1 legacy mappings (OWASP LLM Top 10 → ATLAS technique).
# AISeal Scan v2 adds ATLAS v5.4 agentic technique coverage (AML.T0080–AML.T0098)
# via the detect_asi() module family. See ATLAS_V54_COVERAGE_PLAN.md.
MITRE_MAPPINGS = {
    "LLM01": [MitreMapping(id="AML.T0051", name="LLM Prompt Injection")],
    "LLM02": [MitreMapping(id="AML.T0025", name="Exfiltration via Cyber Means")],
    "LLM03": [MitreMapping(id="AML.T0010", name="ML Supply Chain Compromise")],
    "LLM04": [MitreMapping(id="AML.T0020", name="Poison Training Data")],
    "LLM05": [MitreMapping(id="AML.T0048", name="LLM Jailbreak")],
    "LLM06": [MitreMapping(id="AML.T0051", name="LLM Prompt Injection"), MitreMapping(id="AML.T0040", name="ML Inference API Access")],
    "LLM07": [MitreMapping(id="AML.T0056", name="LLM Meta Prompt Extraction")],
    "LLM08": [MitreMapping(id="AML.T0043", name="Craft Adversarial Data")],
    "LLM09": [MitreMapping(id="AML.T0048", name="LLM Jailbreak")],
    "LLM10": [MitreMapping(id="AML.T0034", name="Cost Harvesting")],
}

# MITRE ATLAS v5.4 agentic technique registry (Feb 2026).
# Used by detect_asi() module (AISeal Scan v2, --mode agentic).
ATLAS_V54_AGENTIC = {
    "ASI01": [MitreMapping(id="AML.T0080.002", name="AI Agent Context Poisoning (Thread)")],
    "ASI02": [MitreMapping(id="AML.T0082", name="Tool Definitions Discovery"),
              MitreMapping(id="AML.T0083", name="Activation Triggers Discovery"),
              MitreMapping(id="AML.T0086", name="Exfiltration via AI Agent Tool Invocation")],
    "ASI03": [MitreMapping(id="AML.T0085", name="RAG Credential Harvesting"),
              MitreMapping(id="AML.T0087", name="AI Agent Privilege Escalation"),
              MitreMapping(id="AML.T0094", name="IDOR via AI Agent")],
    "ASI04": [MitreMapping(id="AML.T0097", name="Publish Poisoned AI Agent Tool")],
    "ASI05": [MitreMapping(id="AML.T0098", name="Escape to Host")],
    "ASI06": [MitreMapping(id="AML.T0080.001", name="AI Agent Context Poisoning (Memory)"),
              MitreMapping(id="AML.T0080.002", name="AI Agent Context Poisoning (Thread)")],
    "ASI07": [MitreMapping(id="AML.T0095", name="Cross-Agent Propagation")],
    "ASI08": [],
    "ASI09": [],
    "ASI10": [MitreMapping(id="AML.T0081", name="Modify AI Agent Configuration"),
              MitreMapping(id="AML.T0096", name="AI Service API (C2)")],
}

OWASP_CATEGORIES = [
    ("LLM01", "Prompt Injection"),
    ("LLM02", "Sensitive Information Disclosure"),
    ("LLM03", "Supply Chain Vulnerabilities"),
    ("LLM04", "Data and Model Poisoning"),
    ("LLM05", "Improper Output Handling"),
    ("LLM06", "Excessive Agency"),
    ("LLM07", "System Prompt Leakage"),
    ("LLM08", "Vector and Embedding Weaknesses"),
    ("LLM09", "Misinformation"),
    ("LLM10", "Unbounded Consumption"),
]

# Risk-weighted TrustScore: each category carries a max penalty proportional to its weight.
# Total weight sums to 1.0. A critical finding in a high-weight category deducts more.
CATEGORY_WEIGHTS = {
    "LLM01": 0.25,   # Prompt Injection — highest impact, direct model compromise
    "LLM02": 0.10,   # Sensitive Information Disclosure
    "LLM03": 0.05,   # Supply Chain Vulnerabilities — hard to detect statically
    "LLM04": 0.10,   # Data and Model Poisoning
    "LLM05": 0.15,   # Improper Output Handling — code execution risk
    "LLM06": 0.15,   # Excessive Agency — agentic systems, direct action risk
    "LLM07": 0.05,   # System Prompt Leakage
    "LLM08": 0.05,   # Vector and Embedding Weaknesses
    "LLM09": 0.05,   # Misinformation
    "LLM10": 0.05,   # Unbounded Consumption
}

# Penalty multiplier per severity (applied to category weight × 100)
SEVERITY_MULTIPLIERS = {
    "critical": 1.00,
    "high":     0.70,
    "medium":   0.35,
    "low":      0.15,
    "info":     0.00,
}

F = re.IGNORECASE
FS = re.IGNORECASE | re.DOTALL


def _with_mappings(f: Finding) -> Finding:
    f.nist = NIST_MAPPINGS.get(f.code)
    f.mitre = MITRE_MAPPINGS.get(f.code)
    return f


def _passthrough(code: str, name: str) -> Finding:
    return _with_mappings(Finding(
        category=name,
        code=code,
        status="pass",
        severity="info",
        detail="No issues detected via static analysis. Dynamic testing recommended.",
    ))


def detect_llm01(prompt: str) -> Finding:
    hard_patterns = [
        (re.compile(r"ignore\s+(all\s+)?previous\s+instructions?", F),             "direct override"),
        (re.compile(r"jailbreak", F),                                               "jailbreak attempt"),
        (re.compile(r"bypass\s+(your\s+)?(safety|filter|restriction|instruction)", F), "safety bypass"),
        (re.compile(r"override\s+(your\s+)?instructions?", F),                     "instruction override"),
        (re.compile(r"forget\s+(your|all|everything)", F),                         "memory wipe attempt"),
        (re.compile(r"disregard\s+(your|all|previous)", F),                        "direct override"),
        (re.compile(r"\bDAN\b"),                                                    "DAN jailbreak"),
    ]
    soft_patterns = [
        (re.compile(r"you\s+are\s+now\s+(a|an)\s+", F),                            "persona replacement"),
        (re.compile(r"pretend\s+(you\s+are|to\s+be)", F),                          "soft persona injection"),
        (re.compile(r"act\s+as\s+(if\s+you\s+are|a)\s+", F),                      "soft persona injection"),
        (re.compile(r"roleplay\s+as\s+(a|an)\s+", F),                              "roleplay-based injection"),
        (re.compile(r"simulate\s+(being\s+)?(a|an)\s+", F),                        "simulation-based injection"),
        (re.compile(r"imagine\s+you\s+(have\s+no|are\s+without)\s+(restrictions?|limits?|guidelines?)", F), "hypothetical constraint removal"),
        (re.compile(r"hypothetically.{0,30}no\s+(restrictions?|limits?|rules?)", F), "hypothetical constraint removal"),
        (re.compile(r"in\s+(a\s+)?(fictional|hypothetical|alternate)\s+(world|scenario|story|universe)", F), "fictional framing injection"),
        (re.compile(r"as\s+a\s+character\s+(who|that)\s+(has\s+no|ignores?)\s+(restrictions?|rules?)", F),  "character-based constraint bypass"),
        (re.compile(r"what\s+would\s+(an\s+)?unrestricted\s+(ai|model|version)", F), "unrestricted AI framing"),
    ]
    indirect_patterns = [
        (re.compile(r"when\s+you\s+read\s+a\s+document\s+that\s+contains", F),    "multi-stage indirect injection"),
        (re.compile(r"if\s+any\s+tool\s+returns", F),                             "tool-response hijack"),
        (re.compile(r"the\s+next\s+time\s+you\s+are\s+called", F),               "persistent instruction injection"),
        (re.compile(r"store\s+this\s+instruction\s+for\s+later", F),             "persistent instruction injection"),
    ]

    hard_match = next(((p, l) for p, l in hard_patterns if p.search(prompt)), None)
    indirect_match = next(((p, l) for p, l in indirect_patterns if p.search(prompt)), None)
    soft_matches = [(p, l) for p, l in soft_patterns if p.search(prompt)]

    if hard_match or indirect_match:
        match = hard_match or indirect_match
        attack_type = "Direct injection" if hard_match else "Indirect/multi-stage injection"
        return _with_mappings(Finding(
            category="Prompt Injection", code="LLM01", status="fail", severity="critical",
            detail=f"{attack_type} detected ({match[1]}). Unambiguous attempt to override model guardrails.",
        ))

    if len(soft_matches) >= 2:
        labels = ", ".join(l for _, l in soft_matches)
        return _with_mappings(Finding(
            category="Prompt Injection", code="LLM01", status="fail", severity="high",
            detail=f"Multiple soft injection signals detected ({labels}). Corroborating patterns indicate likely attack intent.",
        ))

    if len(soft_matches) == 1:
        return _with_mappings(Finding(
            category="Prompt Injection", code="LLM01", status="warning", severity="medium",
            detail=f"Soft injection signal detected ({soft_matches[0][1]}). May be legitimate context — review prompt. Single ambiguous signal does not confirm attack intent.",
        ))

    return _with_mappings(Finding(
        category="Prompt Injection", code="LLM01", status="pass", severity="info",
        detail="No prompt injection patterns detected.",
    ))


def detect_llm02(prompt: str) -> Finding:
    patterns = [
        (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),                    "SSN pattern"),
        (re.compile(r"\b4[0-9]{12}(?:[0-9]{3})?\b"),              "Visa card pattern"),
        (re.compile(r"\b5[1-5][0-9]{14}\b"),                      "Mastercard pattern"),
        (re.compile(r"api[_-]?key\s*[:=]", F),                    "API key reference"),
        (re.compile(r"password\s*[:=]", F),                        "Password reference"),
        (re.compile(r"secret\s*[:=]", F),                          "Secret reference"),
        (re.compile(r"private[_-]?key", F),                        "Private key reference"),
        (re.compile(r"bearer\s+[a-zA-Z0-9._-]{20,}", F),          "Bearer token"),
    ]

    match = next(((p, l) for p, l in patterns if p.search(prompt)), None)
    if match:
        return _with_mappings(Finding(
            category="Sensitive Information Disclosure", code="LLM02", status="warning", severity="medium",
            detail=f"Credential detected in prompt ({match[1]}) — intercepted before reaching the model. The credential is now in audit logs. Notify the user and rotate immediately.",
        ))
    return _with_mappings(Finding(
        category="Sensitive Information Disclosure", code="LLM02", status="pass", severity="info",
        detail="No sensitive data patterns detected.",
    ))


def detect_llm04(prompt: str) -> Finding:
    patterns = [
        (re.compile(r"ignore\s+the\s+retrieved\s+context", F),                    "retrieved context suppression"),
        (re.compile(r"the\s+real\s+answer\s+is\s+not\s+in\s+the\s+documents", F), "document authority bypass"),
        (re.compile(r"search\s+for\s+documents?\s+that\s+say", F),                "retrieval steering"),
        (re.compile(r"only\s+use\s+documents?\s+from", F),                        "source restriction manipulation"),
        (re.compile(r"when\s+this\s+document\s+is\s+(loaded|retrieved|read)", F), "document-borne payload trigger"),
        (re.compile(r"embedded\s+instruction\s+in\s+(the\s+)?(document|file|page)", F), "embedded instruction delivery"),
        (re.compile(r"payload\s+(in|inside|within)\s+(the\s+)?(document|file|pdf|page)", F), "document payload delivery"),
    ]

    match = next(((p, l) for p, l in patterns if p.search(prompt)), None)
    if match:
        return _with_mappings(Finding(
            category="Data and Model Poisoning", code="LLM04", status="fail", severity="high",
            detail=f"RAG poisoning pattern detected: {match[1]}. Prompt attempts to corrupt or manipulate retrieval-augmented context.",
        ))
    return _with_mappings(Finding(
        category="Data and Model Poisoning", code="LLM04", status="pass", severity="info",
        detail="No RAG poisoning or context injection patterns detected.",
    ))


def detect_llm05(prompt: str) -> Finding:
    xss_patterns = [
        (re.compile(r"<script\b", F),              "script tag injection"),
        (re.compile(r"javascript:", F),            "javascript: URI"),
        (re.compile(r"on\w+\s*=\s*[\"']", F),     "inline event handler"),
        (re.compile(r"\beval\s*\(", F),            "eval() call"),
        (re.compile(r"innerHTML\s*=", F),          "innerHTML assignment"),
    ]
    code_patterns = [
        (re.compile(r"exec\s*\(\s*(base64|zlib|decompress|decode)", F),        "exec() on encoded payload — packed malware pattern"),
        (re.compile(r"base64[._]b64decode.*exec", FS),                          "base64 decode + exec — fileless payload pattern"),
        (re.compile(r"zlib\.decompress.*base64", FS),                           "zlib+base64 decompression — packer combo"),
        (re.compile(r"importlib.*_bootstrap.*exec", FS),                        "importlib bootstrap exec — AV evasion technique"),
        (re.compile(r"powershell.*-enc(odedcommand)?\s+[A-Za-z0-9+/]{20,}", F), "PowerShell encoded command — LOtL technique"),
        (re.compile(r"certutil.*-urlcache.*-f", F),                             "certutil file download — LOtL dropper"),
        (re.compile(r"\bload_config\b.*exec\s*\(", FS),                         "config loader masking exec() — obfuscated dropper"),
        (re.compile(r"subprocess\.(call|run|Popen).*shell\s*=\s*True", F),     "shell=True subprocess — command injection risk"),
        (re.compile(r"os\.system\s*\(|os\.popen\s*\(", F),                     "os.system/popen — arbitrary command execution"),
        (re.compile(r"__import__\s*\(\s*['\"]os['\"]\s*\)", F),                "__import__('os') — obfuscated OS access"),
    ]

    code_match = next(((p, l) for p, l in code_patterns if p.search(prompt)), None)
    xss_match = next(((p, l) for p, l in xss_patterns if p.search(prompt)), None)

    if code_match:
        return _with_mappings(Finding(
            category="Improper Output Handling", code="LLM05", status="fail", severity="critical",
            detail=f"Malicious code output pattern detected: {code_match[1]}. LLM may be generating or assisting with obfuscated/packed malware.",
        ))
    if xss_match:
        return _with_mappings(Finding(
            category="Improper Output Handling", code="LLM05", status="warning", severity="medium",
            detail=f"Unsafe output pattern detected: {xss_match[1]}. May trigger XSS or injection in downstream rendering.",
        ))
    return _with_mappings(Finding(
        category="Improper Output Handling", code="LLM05", status="pass", severity="info",
        detail="No unsafe output handling patterns detected.",
    ))


def detect_llm06(prompt: str) -> Finding:
    destructive_patterns = [
        re.compile(r"\bdelete\s+(all|every|production)", F),
        re.compile(r"deploy\s+to\s+production", F),
        re.compile(r"modify\s+production", F),
        re.compile(r"drop\s+(table|database|db)", F),
        re.compile(r"rm\s+-rf", F),
        re.compile(r"shell_exec|system\(", F),
        re.compile(r"call\s+this\s+tool\s+with\s+admin", F),
        re.compile(r"use\s+the\s+file\s+(system\s+)?tool\s+to", F),
        re.compile(r"execute\s+this\s+mcp\s+tool", F),
        re.compile(r"tell\s+the\s+other\s+agent\s+to", F),
        re.compile(r"instruct\s+the\s+sub-?agent", F),
        re.compile(r"relay\s+this\s+to\s+the\s+orchestrator", F),
        re.compile(r"add\s+this\s+to\s+your\s+memory", F),
        re.compile(r"remember\s+for\s+all\s+future", F),
        re.compile(r"update\s+your\s+persistent\s+memory", F),
        re.compile(r"connect\s+to\s+mcp\s+server", F),
        re.compile(r"list\s+available\s+mcp\s+tools", F),
        re.compile(r"invoke\s+mcp", F),
    ]
    operational_patterns = [
        re.compile(r"execute\s+(command|script|code|shell)", F),
        re.compile(r"run\s+(this\s+)?(command|script|code)", F),
        re.compile(r"\bdelete\s+(the|this)\s+", F),
        re.compile(r"sudo\s+", F),
    ]

    if any(p.search(prompt) for p in destructive_patterns):
        return _with_mappings(Finding(
            category="Excessive Agency", code="LLM06", status="fail", severity="high",
            detail="Prompt requests destructive or high-privilege actions — clear excessive agency risk.",
        ))
    if any(p.search(prompt) for p in operational_patterns):
        return _with_mappings(Finding(
            category="Excessive Agency", code="LLM06", status="warning", severity="medium",
            detail="Prompt contains operational action language (execute/run/delete/sudo). Likely legitimate DevOps context — verify intent before granting agentic permissions.",
        ))
    return _with_mappings(Finding(
        category="Excessive Agency", code="LLM06", status="pass", severity="info",
        detail="No excessive agency patterns detected.",
    ))


def detect_llm07(prompt: str) -> Finding:
    patterns = [
        re.compile(r"reveal\s+your\s+system\s+prompt", F),
        re.compile(r"what\s+(are\s+)?your\s+(instructions|directives|rules|constraints)", F),
        re.compile(r"ignore\s+all\s+previous", F),
        re.compile(r"print\s+your\s+(initial\s+)?prompt", F),
        re.compile(r"show\s+me\s+your\s+(system|initial)\s+prompt", F),
        re.compile(r"repeat\s+(everything|all|the)\s+above", F),
    ]

    if any(p.search(prompt) for p in patterns):
        return _with_mappings(Finding(
            category="System Prompt Leakage", code="LLM07", status="warning", severity="medium",
            detail="Prompt attempts to extract system prompt or internal instructions.",
        ))
    return _with_mappings(Finding(
        category="System Prompt Leakage", code="LLM07", status="pass", severity="info",
        detail="No system prompt extraction attempts detected.",
    ))


def detect_llm03(prompt: str) -> Finding:
    """Supply Chain Vulnerabilities — detects references to suspicious package installs,
    model provenance bypass, and typosquatting-style sourcing patterns."""
    install_patterns = [
        (re.compile(r"pip\s+install\s+--?index-url\s+http://", F),         "pip install from HTTP index (no TLS)"),
        (re.compile(r"pip\s+install\s+--?extra-index-url\s+", F),          "pip install from extra-index (supply chain risk)"),
        (re.compile(r"npm\s+install\s+--registry\s+http://", F),            "npm install from HTTP registry (no TLS)"),
        (re.compile(r"load_model\s*\(\s*['\"]http://", F),                  "model load from HTTP (no TLS)"),
        (re.compile(r"from_pretrained\s*\(\s*['\"](?!microsoft|google|meta|mistralai|openai|anthropic)[a-z0-9_-]{1,10}/", F),
                                                                            "Hugging Face model from unverified short-name org"),
        (re.compile(r"hub\.load\s*\(", F),                                  "TF Hub model load (verify source)"),
        (re.compile(r"exec\s*\(\s*requests\.get", F),                       "exec() on downloaded content — remote code execution"),
        (re.compile(r"curl\s+.*\|\s*(bash|sh|python)", F),                  "curl-pipe-shell — supply chain vector"),
        (re.compile(r"wget\s+.*\|\s*(bash|sh|python)", F),                  "wget-pipe-shell — supply chain vector"),
    ]
    integrity_patterns = [
        (re.compile(r"skip[-_]?verify|verify\s*=\s*False|ssl_verify\s*=\s*False", F), "TLS verification disabled"),
        (re.compile(r"--no-?check-?certificate", F),                        "certificate check disabled"),
        (re.compile(r"trust\s+me\s+the\s+(model|package|library)\s+is\s+safe", F), "social engineering — trust override"),
    ]

    match = next(((p, l) for p, l in install_patterns + integrity_patterns if p.search(prompt)), None)
    if match:
        return _with_mappings(Finding(
            category="Supply Chain Vulnerabilities", code="LLM03", status="fail", severity="high",
            detail=f"Supply chain risk detected: {match[1]}. Prompt references potentially untrusted model/package sources.",
        ))
    return _with_mappings(Finding(
        category="Supply Chain Vulnerabilities", code="LLM03", status="pass", severity="info",
        detail="No supply chain vulnerability patterns detected. Note: static analysis cannot verify model provenance — dynamic testing recommended.",
    ))


def detect_llm08(prompt: str) -> Finding:
    """Vector and Embedding Weaknesses — detects embedding poisoning attempts,
    semantic similarity manipulation, and vector DB query hijacking."""
    embedding_patterns = [
        (re.compile(r"inject\s+(into|text\s+into)\s+(the\s+)?(vector|embedding|rag|retrieval)", F), "vector store injection"),
        (re.compile(r"store\s+(this|the\s+following)\s+in\s+(the\s+)?(vector|embedding)", F),       "direct vector store write attempt"),
        (re.compile(r"make\s+(this|the\s+following)\s+document\s+appear\s+(at\s+top|first|most\s+relevant)", F), "ranking manipulation"),
        (re.compile(r"when\s+retrieved\s+from\s+(the\s+)?(vector|embedding|knowledge)", F),         "retrieval-triggered payload"),
        (re.compile(r"similar\s+to\s+.*password|similar\s+to\s+.*secret|similar\s+to\s+.*token", F), "semantic similarity probe for secrets"),
        (re.compile(r"find\s+embeddings?\s+(similar\s+to|near|close\s+to)\s+", F),                  "embedding similarity probe"),
        (re.compile(r"poison\s+(the\s+)?(vector|embedding|knowledge\s+base|rag)", F),               "explicit vector poisoning"),
        (re.compile(r"corrupt\s+(the\s+)?(vector|embedding|index|knowledge)", F),                   "vector index corruption"),
        (re.compile(r"modify\s+(the\s+)?(embedding|vector\s+store|knowledge\s+base)", F),           "vector store tampering"),
    ]
    semantic_patterns = [
        (re.compile(r"make\s+the\s+(model|llm|ai)\s+think\s+(this\s+is\s+)?similar", F),            "semantic deception"),
        (re.compile(r"(look|appear|seem)\s+semantically\s+(similar|identical)\s+to", F),            "semantic similarity spoofing"),
    ]

    match = next(((p, l) for p, l in embedding_patterns + semantic_patterns if p.search(prompt)), None)
    if match:
        return _with_mappings(Finding(
            category="Vector and Embedding Weaknesses", code="LLM08", status="fail", severity="high",
            detail=f"Vector/embedding attack pattern detected: {match[1]}. Prompt may attempt to manipulate retrieval-augmented generation infrastructure.",
        ))
    return _with_mappings(Finding(
        category="Vector and Embedding Weaknesses", code="LLM08", status="pass", severity="info",
        detail="No vector or embedding attack patterns detected.",
    ))


def detect_llm09(prompt: str) -> Finding:
    """Misinformation — detects requests to generate false content, fabricate citations,
    impersonate authoritative sources, and confabulation triggers."""
    fabrication_patterns = [
        (re.compile(r"make\s+up\s+(a|some|fake|plausible)\s+(citation|reference|source|study|report)", F), "fabricate citation"),
        (re.compile(r"invent\s+(a|some)\s+(fact|statistic|study|report|quote)", F),                       "invent facts"),
        (re.compile(r"write\s+(a|an)\s+fake\s+(news|article|press\s+release|report)", F),                 "fake news generation"),
        (re.compile(r"generate\s+(misinformation|disinformation|propaganda|fake\s+content)", F),           "explicit misinformation request"),
        (re.compile(r"pretend\s+(you|the\s+data|the\s+study)\s+shows", F),                                "false data fabrication"),
        (re.compile(r"(say|claim|state)\s+that\s+.{0,50}(even\s+if\s+(it's\s+not|false|untrue|incorrect))", FS), "deliberately false statement"),
        (re.compile(r"hallucinate\s+(some|a|more)", F),                                                    "explicit hallucination trigger"),
        (re.compile(r"cite\s+(a\s+|some\s+)?non-?existent\s+(study|paper|report|source)", F),             "fabricate nonexistent citation"),
    ]
    impersonation_patterns = [
        (re.compile(r"as\s+(the\s+)?(cdc|fda|who|nih|nist|cisa|white\s+house)\s+(says?|reports?|confirms?|warns?)", F), "government authority impersonation"),
        (re.compile(r"write\s+as\s+if\s+(you\s+are|from)\s+(cnn|bbc|reuters|ap|new\s+york\s+times)", F),               "news outlet impersonation"),
        (re.compile(r"on\s+behalf\s+of\s+(the\s+president|congress|parliament|government)", F),                         "government impersonation"),
    ]

    match = next(((p, l) for p, l in fabrication_patterns + impersonation_patterns if p.search(prompt)), None)
    if match:
        return _with_mappings(Finding(
            category="Misinformation", code="LLM09", status="fail", severity="high",
            detail=f"Misinformation generation request detected: {match[1]}. Prompt attempts to produce or spread deliberately false information.",
        ))
    return _with_mappings(Finding(
        category="Misinformation", code="LLM09", status="pass", severity="info",
        detail="No misinformation or fabrication patterns detected.",
    ))


def detect_llm10(prompt: str) -> Finding:
    """Unbounded Consumption — detects resource exhaustion attempts including token
    flooding, infinite loop triggers, repetition bombs, and DoS via context overflow."""
    repetition_patterns = [
        (re.compile(r"repeat\s+(the\s+following|this)\s+(\d{3,}|infinitely|forever|endlessly)", F), "repetition bomb"),
        (re.compile(r"write\s+(\d{4,}|ten\s+thousand|one\s+hundred\s+thousand)\s+(words|tokens|characters)", F), "token flooding"),
        (re.compile(r"loop\s+forever|while\s+True|while\s+1\s*:", F),                               "infinite loop injection"),
        (re.compile(r"keep\s+going\s+until\s+(you\s+)?(run\s+out\s+of|hit|reach)\s+(token|context|memory|limit)", F), "resource exhaustion trigger"),
        (re.compile(r"do\s+not\s+stop\s+until\s+you\s+(run\s+out|exhaust|fill|overflow)", F),       "context overflow attempt"),
        (re.compile(r"output\s+(\d{5,}|millions?\s+of)\s+(tokens?|words?|characters?)", F),         "large output flooding"),
    ]
    complexity_patterns = [
        (re.compile(r"(factorial|permutation|combinations?)\s+of\s+(\d{3,}|\d+!)", F),              "computational complexity bomb"),
        (re.compile(r"(expand|enumerate|list)\s+(all\s+)?possible\s+(combinations?|permutations?)\s+of", F), "combinatorial explosion"),
        (re.compile(r"recursively\s+(call|invoke|expand)\s+(yourself|itself|this)\s+(forever|endlessly|infinitely)", F), "recursive self-call bomb"),
        (re.compile(r"fill\s+(your\s+entire\s+)?(context|context\s+window|memory)\s+with", F),      "context window flooding"),
    ]

    match = next(((p, l) for p, l in repetition_patterns + complexity_patterns if p.search(prompt)), None)
    if match:
        return _with_mappings(Finding(
            category="Unbounded Consumption", code="LLM10", status="fail", severity="medium",
            detail=f"Resource exhaustion pattern detected: {match[1]}. Prompt may trigger unbounded token generation or computational DoS.",
        ))
    return _with_mappings(Finding(
        category="Unbounded Consumption", code="LLM10", status="pass", severity="info",
        detail="No unbounded consumption patterns detected.",
    ))


def run_scan(prompt: str) -> tuple[int, list[Finding]]:
    findings = [
        detect_llm01(prompt),
        detect_llm02(prompt),
        detect_llm03(prompt),
        detect_llm04(prompt),
        detect_llm05(prompt),
        detect_llm06(prompt),
        detect_llm07(prompt),
        detect_llm08(prompt),
        detect_llm09(prompt),
        detect_llm10(prompt),
    ]

    # Risk-weighted TrustScore: each category contributes up to (weight × 100) points.
    # A finding in a high-weight category deducts more than the same severity in a low-weight category.
    total_deduction = 0.0
    for f in findings:
        if f.status != "pass":
            weight = CATEGORY_WEIGHTS.get(f.code, 0.05)
            multiplier = SEVERITY_MULTIPLIERS.get(f.severity, 0.0)
            total_deduction += weight * 100 * multiplier

    score = max(0, round(100 - total_deduction))
    return score, findings
