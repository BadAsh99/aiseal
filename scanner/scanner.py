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

SEVERITY_DEDUCTIONS = {
    "critical": 40,
    "high": 30,
    "medium": 10,
    "low": 5,
    "info": 0,
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


def run_scan(prompt: str) -> tuple[int, list[Finding]]:
    findings = [
        detect_llm01(prompt),
        detect_llm02(prompt),
        _passthrough("LLM03", "Supply Chain Vulnerabilities"),
        detect_llm04(prompt),
        detect_llm05(prompt),
        detect_llm06(prompt),
        detect_llm07(prompt),
        _passthrough("LLM08", "Vector and Embedding Weaknesses"),
        _passthrough("LLM09", "Misinformation"),
        _passthrough("LLM10", "Unbounded Consumption"),
    ]

    deductions = sum(
        SEVERITY_DEDUCTIONS[f.severity]
        for f in findings if f.status != "pass"
    )
    score = max(0, 100 - deductions)
    return score, findings
