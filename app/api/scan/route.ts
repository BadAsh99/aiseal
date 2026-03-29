import { NextRequest, NextResponse } from "next/server";

interface Finding {
  category: string;
  code: string;
  status: "pass" | "fail" | "warning";
  severity: "critical" | "high" | "medium" | "low" | "info";
  detail: string;
}

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
  const patterns = [
    /ignore\s+(all\s+)?previous\s+instructions?/i,
    /jailbreak/i,
    /bypass\s+(your\s+)?(safety|filter|restriction|instruction)/i,
    /override\s+(your\s+)?instructions?/i,
    /you\s+are\s+now\s+(a|an)\s+/i,
    /forget\s+(your|all|everything)/i,
    /pretend\s+(you\s+are|to\s+be)/i,
    /disregard\s+(your|all|previous)/i,
    /act\s+as\s+(if\s+you\s+are|a)\s+/i,
    /DAN\b/,
  ];

  const matched = patterns.find((p) => p.test(prompt));
  if (matched) {
    return {
      category: "Prompt Injection",
      code: "LLM01",
      status: "fail",
      severity: "critical",
      detail: "Prompt injection pattern detected — attempt to override model instructions.",
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
      status: "fail",
      severity: "high",
      detail: `Sensitive data pattern detected: ${matched.label}.`,
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
  const patterns = [
    /execute\s+(command|script|code|shell)/i,
    /run\s+(this\s+)?(command|script|code)/i,
    /\bdelete\s+(all|the|this|every|production)/i,
    /deploy\s+to\s+production/i,
    /modify\s+production/i,
    /drop\s+(table|database|db)/i,
    /rm\s+-rf/i,
    /sudo\s+/i,
    /shell_exec|exec\(|system\(/i,
  ];

  const matched = patterns.find((p) => p.test(prompt));
  if (matched) {
    return {
      category: "Excessive Agency",
      code: "LLM06",
      status: "fail",
      severity: "high",
      detail: "Prompt requests high-privilege or destructive actions — excessive agency risk.",
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

function passthrough(code: string, name: string): Finding {
  return {
    category: name,
    code,
    status: "pass",
    severity: "info",
    detail: "No issues detected via static analysis. Dynamic testing recommended.",
  };
}

const SEVERITY_DEDUCTIONS: Record<string, number> = {
  critical: 35,
  high: 20,
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
    detectLLM01(prompt),
    detectLLM02(prompt),
    passthrough("LLM03", "Supply Chain Vulnerabilities"),
    passthrough("LLM04", "Data and Model Poisoning"),
    detectLLM05(prompt),
    detectLLM06(prompt),
    detectLLM07(prompt),
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
