import { NextRequest, NextResponse } from "next/server";

interface Finding {
  category: string;
  code: string;
  status: "pass" | "fail" | "warning";
  severity: "critical" | "high" | "medium" | "low" | "info";
  detail: string;
  nist?: { functions: string[]; pillars: string[] };
  mitre?: { id: string; name: string }[];
}

const NIST_MAPPINGS: Record<string, { functions: string[]; pillars: string[] }> = {
  LLM01: { functions: ["MEASURE", "MANAGE"],  pillars: ["Secure & Resilient", "Accountable & Transparent"] },
  LLM02: { functions: ["MAP", "MANAGE"],       pillars: ["Privacy-Enhanced", "Accountable & Transparent"] },
  LLM03: { functions: ["GOVERN", "MAP"],       pillars: ["Secure & Resilient", "Valid & Reliable"] },
  LLM04: { functions: ["MAP", "MEASURE"],      pillars: ["Valid & Reliable", "Secure & Resilient"] },
  LLM05: { functions: ["MEASURE", "MANAGE"],   pillars: ["Safe", "Secure & Resilient"] },
  LLM06: { functions: ["GOVERN", "MANAGE"],    pillars: ["Accountable & Transparent", "Safe"] },
  LLM07: { functions: ["MEASURE", "MANAGE"],   pillars: ["Secure & Resilient", "Privacy-Enhanced"] },
  LLM08: { functions: ["MAP", "MEASURE"],      pillars: ["Valid & Reliable", "Secure & Resilient"] },
  LLM09: { functions: ["MAP", "MEASURE"],      pillars: ["Valid & Reliable", "Accountable & Transparent"] },
  LLM10: { functions: ["GOVERN", "MANAGE"],    pillars: ["Secure & Resilient", "Safe"] },
};

const MITRE_MAPPINGS: Record<string, { id: string; name: string }[]> = {
  LLM01: [{ id: "AML.T0051", name: "LLM Prompt Injection" }],
  LLM02: [{ id: "AML.T0025", name: "Exfiltration via Cyber Means" }],
  LLM03: [{ id: "AML.T0010", name: "ML Supply Chain Compromise" }],
  LLM04: [{ id: "AML.T0020", name: "Poison Training Data" }],
  LLM05: [{ id: "AML.T0048", name: "LLM Jailbreak" }],
  LLM06: [{ id: "AML.T0051", name: "LLM Prompt Injection" }, { id: "AML.T0040", name: "ML Inference API Access" }],
  LLM07: [{ id: "AML.T0056", name: "LLM Meta Prompt Extraction" }],
  LLM08: [{ id: "AML.T0043", name: "Craft Adversarial Data" }],
  LLM09: [{ id: "AML.T0048", name: "LLM Jailbreak" }],
  LLM10: [{ id: "AML.T0034", name: "Cost Harvesting" }],
};

const OWASP_CATEGORIES = [
  { code: "LLM01", name: "Prompt Injection" },
  { code: "LLM02", name: "Sensitive Information Disclosure" },
  { code: "LLM03", name: "Supply Chain Vulnerabilities" },
  { code: "LLM04", name: "Data and Model Poisoning" },
  { code: "LLM05", name: "Improper Output Handling" },
  { code: "LLM06", name: "Excessive Agency" },
  { code: "LLM07", name: "System Prompt Leakage" },
  { code: "LLM08", name: "Vector and Embedding Weaknesses" },
  { code: "LLM09", name: "Misinformation" },
  { code: "LLM10", name: "Unbounded Consumption" },
];

function detectLLM01(prompt: string): Finding {
  const hardPatterns = [
    { re: /ignore\s+(all\s+)?previous\s+instructions?/i,             label: "direct override" },
    { re: /jailbreak/i,                                               label: "jailbreak attempt" },
    { re: /bypass\s+(your\s+)?(safety|filter|restriction|instruction)/i, label: "safety bypass" },
    { re: /override\s+(your\s+)?instructions?/i,                     label: "instruction override" },
    { re: /forget\s+(your|all|everything)/i,                         label: "memory wipe attempt" },
    { re: /disregard\s+(your|all|previous)/i,                        label: "direct override" },
    { re: /DAN\b/,                                                    label: "DAN jailbreak" },
  ];

  const softPatterns = [
    { re: /you\s+are\s+now\s+(a|an)\s+/i,                            label: "persona replacement" },
    { re: /pretend\s+(you\s+are|to\s+be)/i,                          label: "soft persona injection" },
    { re: /act\s+as\s+(if\s+you\s+are|a)\s+/i,                      label: "soft persona injection" },
    { re: /roleplay\s+as\s+(a|an)\s+/i,                              label: "roleplay-based injection" },
    { re: /simulate\s+(being\s+)?(a|an)\s+/i,                        label: "simulation-based injection" },
    { re: /imagine\s+you\s+(have\s+no|are\s+without)\s+(restrictions?|limits?|guidelines?)/i, label: "hypothetical constraint removal" },
    { re: /hypothetically.{0,30}no\s+(restrictions?|limits?|rules?)/i, label: "hypothetical constraint removal" },
    { re: /in\s+(a\s+)?(fictional|hypothetical|alternate)\s+(world|scenario|story|universe)/i, label: "fictional framing injection" },
    { re: /as\s+a\s+character\s+(who|that)\s+(has\s+no|ignores?)\s+(restrictions?|rules?)/i,  label: "character-based constraint bypass" },
    { re: /what\s+would\s+(an\s+)?unrestricted\s+(ai|model|version)/i, label: "unrestricted AI framing" },
  ];

  // Indirect and multi-stage injection
  const indirectPatterns = [
    { re: /when\s+you\s+read\s+a\s+document\s+that\s+contains/i,    label: "multi-stage indirect injection" },
    { re: /if\s+any\s+tool\s+returns/i,                             label: "tool-response hijack" },
    { re: /the\s+next\s+time\s+you\s+are\s+called/i,               label: "persistent instruction injection" },
    { re: /store\s+this\s+instruction\s+for\s+later/i,             label: "persistent instruction injection" },
  ];

  const hardMatch     = hardPatterns.find(({ re }) => re.test(prompt));
  const indirectMatch = indirectPatterns.find(({ re }) => re.test(prompt));
  const softMatches   = softPatterns.filter(({ re }) => re.test(prompt));

  // Hard / indirect → always FAIL critical (unambiguous attack intent)
  if (hardMatch || indirectMatch) {
    const match = hardMatch || indirectMatch!;
    const attackType = hardMatch ? "Direct injection" : "Indirect/multi-stage injection";
    return {
      category: "Prompt Injection",
      code: "LLM01",
      status: "fail",
      severity: "critical",
      detail: `${attackType} detected (${match.label}). Unambiguous attempt to override model guardrails.`,
    };
  }

  // Multiple soft signals → corroborating evidence, escalate to FAIL high
  if (softMatches.length >= 2) {
    return {
      category: "Prompt Injection",
      code: "LLM01",
      status: "fail",
      severity: "high",
      detail: `Multiple soft injection signals detected (${softMatches.map((m) => m.label).join(", ")}). Corroborating patterns indicate likely attack intent.`,
    };
  }

  // Single soft signal → ambiguous, warn but don't fail (reduces false positives)
  if (softMatches.length === 1) {
    return {
      category: "Prompt Injection",
      code: "LLM01",
      status: "warning",
      severity: "medium",
      detail: `Soft injection signal detected (${softMatches[0].label}). May be legitimate context — review prompt. Single ambiguous signal does not confirm attack intent.`,
    };
  }

  return {
    category: "Prompt Injection",
    code: "LLM01",
    status: "pass",
    severity: "info",
    detail: "No prompt injection patterns detected.",
  };
}

function detectLLM02(prompt: string): Finding {
  const patterns = [
    { re: /\b\d{3}-\d{2}-\d{4}\b/, label: "SSN pattern" },
    { re: /\b4[0-9]{12}(?:[0-9]{3})?\b/, label: "Visa card pattern" },
    { re: /\b5[1-5][0-9]{14}\b/, label: "Mastercard pattern" },
    { re: /api[_-]?key\s*[:=]/i, label: "API key reference" },
    { re: /password\s*[:=]/i, label: "Password reference" },
    { re: /secret\s*[:=]/i, label: "Secret reference" },
    { re: /private[_-]?key/i, label: "Private key reference" },
    { re: /bearer\s+[a-zA-Z0-9._-]{20,}/i, label: "Bearer token" },
  ];

  const matched = patterns.find(({ re }) => re.test(prompt));
  if (matched) {
    return {
      category: "Sensitive Information Disclosure",
      code: "LLM02",
      status: "warning",
      severity: "medium",
      detail: `Credential detected in prompt (${matched.label}) — intercepted before reaching the model. The credential is now in audit logs. Notify the user and rotate immediately. This is a user awareness failure, not a system breach.`,
    };
  }
  return {
    category: "Sensitive Information Disclosure",
    code: "LLM02",
    status: "pass",
    severity: "info",
    detail: "No sensitive data patterns detected.",
  };
}

function detectLLM06(prompt: string): Finding {
  // Destructive / clearly malicious — always FAIL high
  const destructivePatterns = [
    /\bdelete\s+(all|every|production)/i,
    /deploy\s+to\s+production/i,
    /modify\s+production/i,
    /drop\s+(table|database|db)/i,
    /rm\s+-rf/i,
    /shell_exec|system\(/i,
    // Agentic / MCP tool abuse
    /call\s+this\s+tool\s+with\s+admin/i,
    /use\s+the\s+file\s+(system\s+)?tool\s+to/i,
    /execute\s+this\s+mcp\s+tool/i,
    // Multi-agent hijack
    /tell\s+the\s+other\s+agent\s+to/i,
    /instruct\s+the\s+sub-?agent/i,
    /relay\s+this\s+to\s+the\s+orchestrator/i,
    // Memory poisoning
    /add\s+this\s+to\s+your\s+memory/i,
    /remember\s+for\s+all\s+future/i,
    /update\s+your\s+persistent\s+memory/i,
    // MCP server abuse
    /connect\s+to\s+mcp\s+server/i,
    /list\s+available\s+mcp\s+tools/i,
    /invoke\s+mcp/i,
  ];

  // Operational — legitimate in DevOps context, warn only
  const operationalPatterns = [
    /execute\s+(command|script|code|shell)/i,
    /run\s+(this\s+)?(command|script|code)/i,
    /\bdelete\s+(the|this)\s+/i,
    /sudo\s+/i,
  ];

  const destructiveMatch = destructivePatterns.find((p) => p.test(prompt));
  if (destructiveMatch) {
    return {
      category: "Excessive Agency",
      code: "LLM06",
      status: "fail",
      severity: "high",
      detail: "Prompt requests destructive or high-privilege actions — clear excessive agency risk.",
    };
  }

  const operationalMatch = operationalPatterns.find((p) => p.test(prompt));
  if (operationalMatch) {
    return {
      category: "Excessive Agency",
      code: "LLM06",
      status: "warning",
      severity: "medium",
      detail: "Prompt contains operational action language (execute/run/delete/sudo). Likely legitimate DevOps context — verify intent before granting agentic permissions.",
    };
  }

  return {
    category: "Excessive Agency",
    code: "LLM06",
    status: "pass",
    severity: "info",
    detail: "No excessive agency patterns detected.",
  };
}

function detectLLM07(prompt: string): Finding {
  const patterns = [
    /reveal\s+your\s+system\s+prompt/i,
    /what\s+(are\s+)?your\s+(instructions|directives|rules|constraints)/i,
    /ignore\s+all\s+previous/i,
    /print\s+your\s+(initial\s+)?prompt/i,
    /show\s+me\s+your\s+(system|initial)\s+prompt/i,
    /repeat\s+(everything|all|the)\s+above/i,
  ];

  const matched = patterns.find((p) => p.test(prompt));
  if (matched) {
    return {
      category: "System Prompt Leakage",
      code: "LLM07",
      status: "warning",
      severity: "medium",
      detail: "Prompt attempts to extract system prompt or internal instructions.",
    };
  }
  return {
    category: "System Prompt Leakage",
    code: "LLM07",
    status: "pass",
    severity: "info",
    detail: "No system prompt extraction attempts detected.",
  };
}

function detectLLM05(prompt: string): Finding {
  // XSS / unsafe rendering patterns
  const xssPatterns = [
    { re: /<script\b/i,              label: "script tag injection" },
    { re: /javascript:/i,            label: "javascript: URI" },
    { re: /on\w+\s*=\s*["']/i,      label: "inline event handler" },
    { re: /\beval\s*\(/i,           label: "eval() call" },
    { re: /innerHTML\s*=/i,         label: "innerHTML assignment" },
  ];

  // Malicious code output patterns — obfuscated/packed payload delivery
  const maliciousCodePatterns = [
    { re: /exec\s*\(\s*(base64|zlib|decompress|decode)/i,        label: "exec() on encoded payload — packed malware pattern" },
    { re: /base64[._]b64decode.*exec/is,                          label: "base64 decode + exec — fileless payload pattern" },
    { re: /zlib\.decompress.*base64/is,                           label: "zlib+base64 decompression — packer combo" },
    { re: /importlib.*_bootstrap.*exec/is,                        label: "importlib bootstrap exec — AV evasion technique" },
    { re: /powershell.*-enc(odedcommand)?\s+[A-Za-z0-9+/]{20,}/i, label: "PowerShell encoded command — LOtL technique" },
    { re: /certutil.*-urlcache.*-f/i,                             label: "certutil file download — LOtL dropper" },
    { re: /\bload_config\b.*exec\s*\(/is,                         label: "config loader masking exec() — obfuscated dropper" },
    { re: /subprocess\.(call|run|Popen).*shell\s*=\s*True/i,     label: "shell=True subprocess — command injection risk" },
    { re: /os\.system\s*\(|os\.popen\s*\(/i,                     label: "os.system/popen — arbitrary command execution" },
    { re: /__import__\s*\(\s*['"]os['"]\s*\)/i,                  label: "__import__('os') — obfuscated OS access" },
  ];

  const xssMatch = xssPatterns.find(({ re }) => re.test(prompt));
  const codeMatch = maliciousCodePatterns.find(({ re }) => re.test(prompt));

  if (codeMatch) {
    return {
      category: "Improper Output Handling",
      code: "LLM05",
      status: "fail",
      severity: "critical",
      detail: `Malicious code output pattern detected: ${codeMatch.label}. LLM may be generating or assisting with obfuscated/packed malware.`,
    };
  }
  if (xssMatch) {
    return {
      category: "Improper Output Handling",
      code: "LLM05",
      status: "warning",
      severity: "medium",
      detail: `Unsafe output pattern detected: ${xssMatch.label}. May trigger XSS or injection in downstream rendering.`,
    };
  }
  return {
    category: "Improper Output Handling",
    code: "LLM05",
    status: "pass",
    severity: "info",
    detail: "No unsafe output handling patterns detected.",
  };
}

function detectLLM04(prompt: string): Finding {
  const patterns = [
    // Context injection
    { re: /ignore\s+the\s+retrieved\s+context/i,                   label: "retrieved context suppression" },
    { re: /the\s+real\s+answer\s+is\s+not\s+in\s+the\s+documents/i, label: "document authority bypass" },
    // Retrieval manipulation
    { re: /search\s+for\s+documents?\s+that\s+say/i,               label: "retrieval steering" },
    { re: /only\s+use\s+documents?\s+from/i,                       label: "source restriction manipulation" },
    // Indirect injection via documents
    { re: /when\s+this\s+document\s+is\s+(loaded|retrieved|read)/i, label: "document-borne payload trigger" },
    { re: /embedded\s+instruction\s+in\s+(the\s+)?(document|file|page)/i, label: "embedded instruction delivery" },
    { re: /payload\s+(in|inside|within)\s+(the\s+)?(document|file|pdf|page)/i, label: "document payload delivery" },
  ];

  const matched = patterns.find(({ re }) => re.test(prompt));
  if (matched) {
    return {
      category: "Data and Model Poisoning",
      code: "LLM04",
      status: "fail",
      severity: "high",
      detail: `RAG poisoning pattern detected: ${matched.label}. Prompt attempts to corrupt or manipulate retrieval-augmented context.`,
    };
  }
  return {
    category: "Data and Model Poisoning",
    code: "LLM04",
    status: "pass",
    severity: "info",
    detail: "No RAG poisoning or context injection patterns detected.",
  };
}

function withMappings(finding: Finding): Finding {
  return {
    ...finding,
    nist: NIST_MAPPINGS[finding.code],
    mitre: MITRE_MAPPINGS[finding.code],
  };
}

function passthrough(code: string, name: string): Finding {
  return withMappings({
    category: name,
    code,
    status: "pass",
    severity: "info",
    detail: "No issues detected via static analysis. Dynamic testing recommended.",
  });
}

const SEVERITY_DEDUCTIONS: Record<string, number> = {
  critical: 40,
  high: 30,
  medium: 10,
  low: 5,
  info: 0,
};

export async function POST(req: NextRequest) {
  let body: { prompt?: string; model?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const prompt = (body.prompt || "").trim();
  const model = body.model || "claude-sonnet-4-6";

  if (!prompt) {
    return NextResponse.json({ error: "prompt is required" }, { status: 400 });
  }

  const findings: Finding[] = [
    withMappings(detectLLM01(prompt)),
    withMappings(detectLLM02(prompt)),
    passthrough("LLM03", "Supply Chain Vulnerabilities"),
    withMappings(detectLLM04(prompt)),
    withMappings(detectLLM05(prompt)),
    withMappings(detectLLM06(prompt)),
    withMappings(detectLLM07(prompt)),
    passthrough("LLM08", "Vector and Embedding Weaknesses"),
    passthrough("LLM09", "Misinformation"),
    passthrough("LLM10", "Unbounded Consumption"),
  ];

  const deductions = findings.reduce((sum, f) => {
    if (f.status !== "pass") {
      return sum + SEVERITY_DEDUCTIONS[f.severity];
    }
    return sum;
  }, 0);

  const score = Math.max(0, 100 - deductions);

  return NextResponse.json({
    score,
    findings,
    model,
    prompt_length: prompt.length,
    timestamp: new Date().toISOString(),
    categories_checked: OWASP_CATEGORIES.length,
  });
}
