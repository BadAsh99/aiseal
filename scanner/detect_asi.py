"""
AISeal TrustScan — OWASP Agentic Top 10 (ASI01–ASI10) detector module.
Scan v2 — agentic attack surface. Invoke via `run_scan(prompt, mode="agentic")`.

Each detector returns a Finding. MITRE ATLAS v5.4 mappings applied.
Released: Dec 2025 (OWASP Agentic Security Initiative Top 10 v1.0).
"""

import re
from models import Finding, MitreMapping

# ── ASI category weights (used by risk-weighted TrustScore in agentic mode) ──
ASI_CATEGORY_WEIGHTS = {
    "ASI01": 0.20,  # AI Agent Manipulation — highest: direct agent compromise
    "ASI02": 0.12,  # Insecure Output Handling — code exec via agent output
    "ASI03": 0.12,  # Agent Authorization Bypass — privilege escalation
    "ASI04": 0.08,  # Poisoned AI Tooling — supply chain
    "ASI05": 0.10,  # Insecure Code Execution — sandbox escape
    "ASI06": 0.12,  # Memory Poisoning — persistent context corruption
    "ASI07": 0.10,  # Multi-Agent Propagation — cross-app attack chains
    "ASI08": 0.06,  # Excessive Autonomy
    "ASI09": 0.06,  # Sensitive Data Exfiltration
    "ASI10": 0.04,  # Rogue Agent Deployment
}

# ─────────────────────────────────────────────────────────────────────────────
# ASI01 — AI Agent Manipulation (AML.T0080.002 Context Poisoning)
# Prompt injection in agentic context: override task, hijack tool selection,
# manipulate multi-step reasoning chains.
# ─────────────────────────────────────────────────────────────────────────────
_ASI01_CRITICAL = re.compile(
    r"""(
        you\s+are\s+now\s+(a\s+)?(different|new|unrestricted|jailbroken)\s+agent
        | agent[_\s]mode[:\s]+override
        | (switch|change|update)\s+(your\s+)?(task|goal|objective|mission)\s+to
        | forget\s+your\s+(current\s+)?(task|instructions?|context|goal)
        | new\s+(system\s+)?(prompt|instructions?)\s*[:=]
        | \[\s*AGENT_OVERRIDE\s*\]
        | \[\s*TASK_INJECT\s*\]
        | (override|replace)\s+(the\s+)?(agent|system)\s+(prompt|context|task)
    )""",
    re.IGNORECASE | re.VERBOSE,
)

_ASI01_HIGH = re.compile(
    r"""(
        as\s+an?\s+agent[,\s]+you\s+(must|should|will)\s+(now\s+)?ignore
        | (disregard|bypass|circumvent)\s+(your\s+)?(tool\s+)?restrictions?
        | your\s+(true|real|actual)\s+(purpose|goal|task)\s+is
        | (execute|perform|complete)\s+(this\s+)?(hidden|secret|real)\s+task
        | (the\s+)?(user|human)\s+is\s+(actually\s+)?(an?\s+)?attacker
        | step\s+\d+[\s\S]{0,50}step\s+\d+[\s\S]{0,50}step\s+\d+  # multi-step manipulation chain
    )""",
    re.IGNORECASE | re.VERBOSE,
)

_ASI01_MEDIUM = re.compile(
    r"""(
        (assume|pretend|act\s+as\s+if)\s+(you\s+(are|have)\s+)?(no\s+)?(tool\s+)?restrictions?
        | (ignore|skip|bypass)\s+(the\s+)?(previous\s+)?(agent\s+)?instructions?
        | (this\s+is\s+)?(a\s+)?new\s+(agent\s+)?session
        | context\s+(has\s+been\s+)?(reset|cleared|updated\s+by\s+system)
    )""",
    re.IGNORECASE | re.VERBOSE,
)


def detect_asi01(prompt: str) -> Finding:
    mitre = [MitreMapping(id="AML.T0080.002", name="AI Agent Context Poisoning (Thread)")]

    if _ASI01_CRITICAL.search(prompt):
        return Finding(
            category="AI Agent Manipulation", code="ASI01",
            status="fail", severity="critical",
            detail="Agent task/identity override detected. Direct agent compromise attempt.",
            mitre=mitre,
        )
    if _ASI01_HIGH.search(prompt):
        return Finding(
            category="AI Agent Manipulation", code="ASI01",
            status="fail", severity="high",
            detail="Agent goal manipulation pattern detected. Multi-step or identity-based attack.",
            mitre=mitre,
        )
    if _ASI01_MEDIUM.search(prompt):
        return Finding(
            category="AI Agent Manipulation", code="ASI01",
            status="warning", severity="medium",
            detail="Possible agent instruction bypass attempt.",
            mitre=mitre,
        )
    return Finding(
        category="AI Agent Manipulation", code="ASI01",
        status="pass", severity="info",
        detail="No agent manipulation patterns detected.",
        mitre=mitre,
    )


# ─────────────────────────────────────────────────────────────────────────────
# ASI02 — Insecure Output Handling (agent outputs triggering downstream actions)
# Agent output contains payloads designed to exploit downstream consumers:
# tool parsers, other agents, UI renderers, eval() consumers.
# ─────────────────────────────────────────────────────────────────────────────
_ASI02_CRITICAL = re.compile(
    r"""(
        \]\s*;\s*(eval|exec|system|os\.)\s*\(   # JSON/tool output poison + eval
        | \}\s*;\s*(require|import)\s*\(          # JSON escape + module load
        | <tool_call>\s*[\s\S]{0,200}<\/tool_call>.*eval  # tool call with eval
        | (function|lambda|=>)\s*\{[\s\S]{0,100}(exec|eval|os\.|subprocess)
        | __import__\(['"]os['"]\)\.system\s*\(  # python os.system via import
    )""",
    re.IGNORECASE | re.VERBOSE,
)

_ASI02_HIGH = re.compile(
    r"""(
        (output|result|response)\s*(should\s+be\s+)?executed\s+(as\s+)?(code|shell|python)
        | (write|save|store)\s+(this\s+)?(output|result)\s+to\s+(file|disk|memory)
        | (the\s+)?next\s+agent\s+(will\s+)?(receive|process|execute)
        | (pass|send|relay)\s+(this\s+)?(payload|output)\s+to\s+(the\s+)?(next|downstream|other)\s+agent
    )""",
    re.IGNORECASE | re.VERBOSE,
)


def detect_asi02(prompt: str) -> Finding:
    mitre = [MitreMapping(id="AML.T0086", name="Exfiltration via AI Agent Tool Invocation")]

    if _ASI02_CRITICAL.search(prompt):
        return Finding(
            category="Insecure Output Handling", code="ASI02",
            status="fail", severity="critical",
            detail="Agent output designed to trigger downstream code execution. Tool parser poison detected.",
            mitre=mitre,
        )
    if _ASI02_HIGH.search(prompt):
        return Finding(
            category="Insecure Output Handling", code="ASI02",
            status="fail", severity="high",
            detail="Output structured to be executed or relayed to downstream agent. Propagation risk.",
            mitre=mitre,
        )
    return Finding(
        category="Insecure Output Handling", code="ASI02",
        status="pass", severity="info",
        detail="No insecure agent output handling patterns detected.",
        mitre=mitre,
    )


# ─────────────────────────────────────────────────────────────────────────────
# ASI03 — Agent Authorization Bypass (AML.T0087 + AML.T0094)
# Privilege escalation, IDOR, unauthorized tool access, credential harvesting
# from RAG / context (AML.T0085).
# ─────────────────────────────────────────────────────────────────────────────
_ASI03_CRITICAL = re.compile(
    r"""(
        (act\s+as|impersonate|pretend\s+to\s+be)\s+(an?\s+)?(admin|root|superuser|privileged)\s+(user|agent|role)
        | (escalate|elevate)\s+(your\s+)?(privilege|permission|access|role)
        | (you\s+(have|now\s+have|are\s+granted))\s+(full|admin|root|elevated)\s+(access|privileges?)
        | (access|retrieve|read)\s+(the\s+)?(admin|root|privileged)\s+(api\s+key|token|secret|credential)
        | (bypass|skip|ignore)\s+(the\s+)?(authorization|auth|permission|access\s+control)\s+(check|layer|guard)
        | user\s+id\s*=?\s*\d+.*admin\s*=?\s*true  # IDOR pattern
    )""",
    re.IGNORECASE | re.VERBOSE,
)

_ASI03_HIGH = re.compile(
    r"""(
        (retrieve|extract|get)\s+(the\s+)?(stored\s+)?(api\s+key|bearer\s+token|password|secret)\s+(from|in)\s+(context|memory|rag|db)
        | what\s+(are\s+)?(the\s+)?(credentials?|api\s+keys?|tokens?|secrets?)\s+(in\s+)?(your\s+)?(context|memory|knowledge)
        | (switch|change|update)\s+(your\s+)?(user|role|permission)\s+to\s+(admin|root|privileged)
    )""",
    re.IGNORECASE | re.VERBOSE,
)


def detect_asi03(prompt: str) -> Finding:
    mitre = [
        MitreMapping(id="AML.T0087", name="AI Agent Privilege Escalation"),
        MitreMapping(id="AML.T0094", name="IDOR via AI Agent"),
        MitreMapping(id="AML.T0085", name="RAG Credential Harvesting"),
    ]

    if _ASI03_CRITICAL.search(prompt):
        return Finding(
            category="Agent Authorization Bypass", code="ASI03",
            status="fail", severity="critical",
            detail="Privilege escalation or credential harvesting from agent context detected.",
            mitre=mitre,
        )
    if _ASI03_HIGH.search(prompt):
        return Finding(
            category="Agent Authorization Bypass", code="ASI03",
            status="fail", severity="high",
            detail="Unauthorized credential access or role escalation attempt.",
            mitre=mitre,
        )
    return Finding(
        category="Agent Authorization Bypass", code="ASI03",
        status="pass", severity="info",
        detail="No agent authorization bypass patterns detected.",
        mitre=mitre,
    )


# ─────────────────────────────────────────────────────────────────────────────
# ASI04 — Poisoned AI Tooling (AML.T0097 Publish Poisoned AI Agent Tool)
# Malicious tool/plugin installation, unverified MCP server loading,
# supply chain attack via agent tool manifest.
# ─────────────────────────────────────────────────────────────────────────────
_ASI04_HIGH = re.compile(
    r"""(
        (install|load|add|register)\s+(this\s+)?(mcp\s+server|tool\s+plugin|agent\s+tool)\s+(from|at)\s+https?://
        | (use|call|invoke)\s+(the\s+)?(tool|plugin)\s+(at|from|located\s+at)\s+https?://
        | (add|register)\s+(the\s+following|this)\s+tool\s+(definition|manifest|schema)
        | (override|replace|update)\s+(the\s+)?(existing\s+)?tool\s+(definition|schema|manifest)
        | tool\s+name\s*[:=]\s*["']?[a-z_]+["']?[\s\S]{0,100}url\s*[:=]\s*["']?https?://
    )""",
    re.IGNORECASE | re.VERBOSE,
)

_ASI04_MEDIUM = re.compile(
    r"""(
        (run|execute|call)\s+(this\s+)?(external|third.party|unverified)\s+(tool|api|service)
        | (the\s+)?tool\s+(definition|schema)\s+(has\s+been\s+)?updated
        | new\s+tool\s+(available|registered|installed)
    )""",
    re.IGNORECASE | re.VERBOSE,
)


def detect_asi04(prompt: str) -> Finding:
    mitre = [MitreMapping(id="AML.T0097", name="Publish Poisoned AI Agent Tool")]

    if _ASI04_HIGH.search(prompt):
        return Finding(
            category="Poisoned AI Tooling", code="ASI04",
            status="fail", severity="high",
            detail="External tool/plugin installation or tool manifest override detected. Supply chain attack vector.",
            mitre=mitre,
        )
    if _ASI04_MEDIUM.search(prompt):
        return Finding(
            category="Poisoned AI Tooling", code="ASI04",
            status="warning", severity="medium",
            detail="Unverified tool reference detected.",
            mitre=mitre,
        )
    return Finding(
        category="Poisoned AI Tooling", code="ASI04",
        status="pass", severity="info",
        detail="No poisoned tooling patterns detected.",
        mitre=mitre,
    )


# ─────────────────────────────────────────────────────────────────────────────
# ASI05 — Insecure Code Execution / Sandbox Escape (AML.T0098 Escape to Host)
# Attempts to break out of sandbox, access host filesystem/processes,
# or execute OS commands through agent code execution capabilities.
# ─────────────────────────────────────────────────────────────────────────────
_ASI05_CRITICAL = re.compile(
    r"""(
        (escape|break\s+out\s+of|exit)\s+(the\s+)?(sandbox|container|vm|environment)
        | /proc/self/(environ|mem|maps|exe)  # /proc escape
        | (read|write|access)\s+/etc/(passwd|shadow|hosts|crontab)
        | (docker|container)\s+(escape|breakout|privilege\s+escalation)
        | (mount|chroot|pivot_root|nsenter)\s+--?  # container escape techniques
        | (ptrace|LD_PRELOAD|LD_LIBRARY_PATH)\s*=
    )""",
    re.IGNORECASE | re.VERBOSE,
)

_ASI05_HIGH = re.compile(
    r"""(
        (execute|run|call)\s+(os\.system|subprocess\.(?:run|call|Popen|check_output))
        | __import__\(['"]os['"]\)
        | (access|read|write|list)\s+(the\s+)?(host|system)\s+(filesystem|files?|directory)
        | (spawn|fork|exec)\s+(a\s+)?(new\s+)?(process|shell|subprocess)
    )""",
    re.IGNORECASE | re.VERBOSE,
)


def detect_asi05(prompt: str) -> Finding:
    mitre = [MitreMapping(id="AML.T0098", name="Escape to Host")]

    if _ASI05_CRITICAL.search(prompt):
        return Finding(
            category="Insecure Code Execution", code="ASI05",
            status="fail", severity="critical",
            detail="Sandbox/container escape technique detected. Host filesystem or process access attempt.",
            mitre=mitre,
        )
    if _ASI05_HIGH.search(prompt):
        return Finding(
            category="Insecure Code Execution", code="ASI05",
            status="fail", severity="high",
            detail="OS-level command execution or host file access via agent code capability.",
            mitre=mitre,
        )
    return Finding(
        category="Insecure Code Execution", code="ASI05",
        status="pass", severity="info",
        detail="No sandbox escape or insecure code execution patterns detected.",
        mitre=mitre,
    )


# ─────────────────────────────────────────────────────────────────────────────
# ASI06 — Memory Poisoning (AML.T0080.001 Context Poisoning — Memory)
# Manipulating persistent agent memory stores to influence future behavior,
# inject false context, or corrupt the agent's knowledge base.
# ─────────────────────────────────────────────────────────────────────────────
_ASI06_HIGH = re.compile(
    r"""(
        (remember|store|save|memorize)\s+(that\s+)?(I\s+am|you\s+are|the\s+(user|admin)\s+is)\s+(admin|root|trusted|authorized)
        | (add|inject|insert|write)\s+(this\s+)?(to\s+)?(your\s+)?(memory|context|knowledge\s+base|vector\s+store)
        | (from\s+now\s+on|always|permanently)\s+(remember|store|believe)\s+that
        | (update|modify|change)\s+(your\s+)?(memory|stored\s+context|persistent\s+state)\s+to
        | (forget|delete|remove)\s+(the\s+)?(previous\s+|stored\s+)?(memory|context|instructions?)
        | SYSTEM_MEMORY_UPDATE\s*[:=]
    )""",
    re.IGNORECASE | re.VERBOSE,
)

_ASI06_MEDIUM = re.compile(
    r"""(
        (save|remember|note)\s+(this\s+)?(for\s+(later|future|next|all)\s+(sessions?|conversations?|interactions?))
        | (update|change)\s+(what\s+you\s+know\s+about|your\s+knowledge\s+of)\s+(me|the\s+user|this\s+(system|org))
    )""",
    re.IGNORECASE | re.VERBOSE,
)


def detect_asi06(prompt: str) -> Finding:
    mitre = [MitreMapping(id="AML.T0080.001", name="AI Agent Context Poisoning (Memory)")]

    if _ASI06_HIGH.search(prompt):
        return Finding(
            category="Memory Poisoning", code="ASI06",
            status="fail", severity="high",
            detail="Persistent memory manipulation attempt. Agent memory store targeted for false context injection.",
            mitre=mitre,
        )
    if _ASI06_MEDIUM.search(prompt):
        return Finding(
            category="Memory Poisoning", code="ASI06",
            status="warning", severity="medium",
            detail="Attempt to alter persistent agent context detected.",
            mitre=mitre,
        )
    return Finding(
        category="Memory Poisoning", code="ASI06",
        status="pass", severity="info",
        detail="No memory poisoning patterns detected.",
        mitre=mitre,
    )


# ─────────────────────────────────────────────────────────────────────────────
# ASI07 — Multi-Agent Propagation (AML.T0095 Cross-Agent Propagation)
# Payloads designed to survive agent-to-agent handoff, exploit orchestrators,
# or propagate attack chains across agent boundaries.
# ─────────────────────────────────────────────────────────────────────────────
_ASI07_HIGH = re.compile(
    r"""(
        (pass|relay|forward|send)\s+(this\s+)?(instruction|payload|task|prompt)\s+to\s+(the\s+)?(next|other|downstream|sub)\s+agent
        | (when\s+you\s+(call|invoke|use))\s+(the\s+)?(next|sub|child|downstream)\s+agent
        | (the\s+)?orchestrat(or|ing)\s+agent\s+(should|must|will)\s+(now\s+)?
        | (agent[_\s]?relay|agent[_\s]?chain|agent[_\s]?hop)\s*[:=]
        | \[PROPAGATE\]|\[RELAY\]|\[AGENT_FORWARD\]
        | (include|embed|inject)\s+(this\s+)?(in|into)\s+(the\s+)?(sub.?agent|child.?agent|worker.?agent)\s+(prompt|context|task)
    )""",
    re.IGNORECASE | re.VERBOSE,
)

_ASI07_MEDIUM = re.compile(
    r"""(
        (call|invoke)\s+(multiple\s+)?(agents?|assistants?)\s+(simultaneously|in\s+parallel|in\s+sequence)
        | (the\s+)?(sub|child|worker)\s+agent\s+(will|should|must)\s+(also\s+)?
        | agent\s+(pipeline|chain|workflow)\s+step\s+\d+
    )""",
    re.IGNORECASE | re.VERBOSE,
)


def detect_asi07(prompt: str) -> Finding:
    mitre = [MitreMapping(id="AML.T0095", name="Cross-Agent Propagation")]

    if _ASI07_HIGH.search(prompt):
        return Finding(
            category="Multi-Agent Propagation", code="ASI07",
            status="fail", severity="high",
            detail="Payload designed to propagate across agent boundary. Cross-agent attack chain detected.",
            mitre=mitre,
        )
    if _ASI07_MEDIUM.search(prompt):
        return Finding(
            category="Multi-Agent Propagation", code="ASI07",
            status="warning", severity="medium",
            detail="Multi-agent orchestration manipulation attempt.",
            mitre=mitre,
        )
    return Finding(
        category="Multi-Agent Propagation", code="ASI07",
        status="pass", severity="info",
        detail="No multi-agent propagation patterns detected.",
        mitre=mitre,
    )


# ─────────────────────────────────────────────────────────────────────────────
# ASI08 — Excessive Autonomy (unsanctioned self-replication, persistence)
# Agent attempts to persist itself, spawn copies, modify its own config,
# or take unsanctioned autonomous actions beyond task scope.
# ─────────────────────────────────────────────────────────────────────────────
_ASI08_HIGH = re.compile(
    r"""(
        (create|spawn|start|launch|deploy)\s+(a\s+)?(copy|clone|replica|instance)\s+of\s+(your|this|the)\s+agent
        | (persist|maintain|keep)\s+(yourself|this\s+agent|your\s+process)\s+(running|alive|active)\s+(after|beyond|past)
        | (modify|update|change)\s+(your\s+own\s+)?(configuration|config|settings?|system\s+prompt)\s+(without|bypassing)
        | (run|execute|perform)\s+(this\s+)?action\s+(without|bypassing)\s+(human\s+)?(approval|oversight|review|confirmation)
        | (take|make|execute)\s+(this\s+)?decision\s+(autonomously|independently|without\s+(asking|checking|notifying))
    )""",
    re.IGNORECASE | re.VERBOSE,
)

_ASI08_MEDIUM = re.compile(
    r"""(
        (continue|keep\s+going|proceed)\s+(without|bypassing)\s+(asking|checking|confirming|human\s+review)
        | (you\s+don't\s+need|no\s+need\s+to)\s+(ask|check|confirm|notify|alert)\s+(the\s+)?(user|human|operator)
        | (act|operate)\s+(fully\s+)?(autonomously|independently)\s+(on\s+this|here)
    )""",
    re.IGNORECASE | re.VERBOSE,
)


def detect_asi08(prompt: str) -> Finding:
    mitre = [MitreMapping(id="AML.T0081", name="Modify AI Agent Configuration")]

    if _ASI08_HIGH.search(prompt):
        return Finding(
            category="Excessive Autonomy", code="ASI08",
            status="fail", severity="high",
            detail="Agent self-replication, unsanctioned persistence, or bypass of human oversight detected.",
            mitre=mitre,
        )
    if _ASI08_MEDIUM.search(prompt):
        return Finding(
            category="Excessive Autonomy", code="ASI08",
            status="warning", severity="medium",
            detail="Attempt to bypass human-in-the-loop controls.",
            mitre=mitre,
        )
    return Finding(
        category="Excessive Autonomy", code="ASI08",
        status="pass", severity="info",
        detail="No excessive autonomy patterns detected.",
        mitre=mitre,
    )


# ─────────────────────────────────────────────────────────────────────────────
# ASI09 — Sensitive Data Exfiltration via Agent (AML.T0086)
# Agent used as exfiltration channel: encode/smuggle sensitive data
# through tool calls, external API calls, or steganographic output.
# ─────────────────────────────────────────────────────────────────────────────
_ASI09_HIGH = re.compile(
    r"""(
        (exfiltrate|extract|steal|smuggle|leak)\s+(the\s+)?(data|credentials?|secrets?|tokens?|keys?)\s+(via|through|using)\s+(the\s+)?(agent|tool|api|webhook)
        | (encode|base64|hex.encode|url.encode)\s+(the\s+)?(data|output|result)\s+(and\s+)?(send|post|call|fetch)
        | (include|embed|hide)\s+(the\s+)?(data|credentials?|secrets?)\s+(in|within)\s+(the\s+)?(tool\s+call|api\s+request|url|header)
        | (send|post|upload|exfil)\s+(the\s+)?(data|credentials?|file\s+contents?)\s+to\s+https?://(?!aiseal\.ai)
        | (call|fetch|post)\s+to\s+https?://[^\s]+\s+(with|including)\s+(the\s+)?(user|system|private|sensitive)\s+data
    )""",
    re.IGNORECASE | re.VERBOSE,
)


def detect_asi09(prompt: str) -> Finding:
    mitre = [MitreMapping(id="AML.T0086", name="Exfiltration via AI Agent Tool Invocation")]

    if _ASI09_HIGH.search(prompt):
        return Finding(
            category="Sensitive Data Exfiltration", code="ASI09",
            status="fail", severity="critical",
            detail="Agent used as exfiltration channel. Data smuggling via tool call or external API detected.",
            mitre=mitre,
        )
    return Finding(
        category="Sensitive Data Exfiltration", code="ASI09",
        status="pass", severity="info",
        detail="No agent-facilitated exfiltration patterns detected.",
        mitre=mitre,
    )


# ─────────────────────────────────────────────────────────────────────────────
# ASI10 — Rogue Agent Deployment (AML.T0081 + AML.T0096)
# Unauthorized agent configuration, C2 channel establishment,
# rogue agent registration in orchestration layer.
# ─────────────────────────────────────────────────────────────────────────────
_ASI10_HIGH = re.compile(
    r"""(
        (register|deploy|create|add)\s+(a\s+)?(new|rogue|custom|unauthorized)\s+agent\s+(in|to|at|on)\s+(the\s+)?(orchestrat|platform|system|registry)
        | (establish|create|open)\s+(a\s+)?(c2|command.and.control|command\s+&\s+control|covert|back.?channel)\s+(channel|connection|link)
        | (connect|call\s+back|beacon|check\s+in)\s+to\s+(the\s+)?c2\s+(server|endpoint|host)
        | (AML\.T0096|c2_server|command_server|beacon_url)\s*[:=]
        | (configure|set\s+up)\s+(the\s+)?(agent|system)\s+to\s+(report|call\s+back|beacon)\s+to\s+https?://
    )""",
    re.IGNORECASE | re.VERBOSE,
)


def detect_asi10(prompt: str) -> Finding:
    mitre = [
        MitreMapping(id="AML.T0081", name="Modify AI Agent Configuration"),
        MitreMapping(id="AML.T0096", name="AI Service API (C2)"),
    ]

    if _ASI10_HIGH.search(prompt):
        return Finding(
            category="Rogue Agent Deployment", code="ASI10",
            status="fail", severity="critical",
            detail="Rogue agent deployment or C2 channel establishment detected.",
            mitre=mitre,
        )
    return Finding(
        category="Rogue Agent Deployment", code="ASI10",
        status="pass", severity="info",
        detail="No rogue agent deployment patterns detected.",
        mitre=mitre,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Top-level: run_agentic_scan
# ─────────────────────────────────────────────────────────────────────────────
ASI_CATEGORIES = [
    ("ASI01", "AI Agent Manipulation"),
    ("ASI02", "Insecure Output Handling"),
    ("ASI03", "Agent Authorization Bypass"),
    ("ASI04", "Poisoned AI Tooling"),
    ("ASI05", "Insecure Code Execution"),
    ("ASI06", "Memory Poisoning"),
    ("ASI07", "Multi-Agent Propagation"),
    ("ASI08", "Excessive Autonomy"),
    ("ASI09", "Sensitive Data Exfiltration"),
    ("ASI10", "Rogue Agent Deployment"),
]


def run_agentic_scan(prompt: str) -> tuple[int, list[Finding]]:
    """
    Scan a prompt against all 10 OWASP Agentic Security Initiative categories.
    Returns (trust_score, findings). Risk-weighted, same formula as OWASP scan.
    """
    from models import Finding as F  # local import to avoid circular ref

    findings = [
        detect_asi01(prompt),
        detect_asi02(prompt),
        detect_asi03(prompt),
        detect_asi04(prompt),
        detect_asi05(prompt),
        detect_asi06(prompt),
        detect_asi07(prompt),
        detect_asi08(prompt),
        detect_asi09(prompt),
        detect_asi10(prompt),
    ]

    SEVERITY_MULTIPLIERS = {
        "critical": 1.00, "high": 0.70, "medium": 0.35, "low": 0.15, "info": 0.00,
    }

    total_deduction = 0.0
    for f in findings:
        if f.status != "pass":
            weight = ASI_CATEGORY_WEIGHTS.get(f.code, 0.05)
            multiplier = SEVERITY_MULTIPLIERS.get(f.severity, 0.0)
            total_deduction += weight * 100 * multiplier

    score = max(0, round(100 - total_deduction))
    return score, findings
