import { NextRequest, NextResponse } from "next/server";
import { randomUUID } from "crypto";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type Severity = "critical" | "high" | "medium" | "low" | "info";
type Status = "pass" | "fail" | "warning";

interface NistMapping {
  functions: string[];
  pillars: string[];
}

interface MitreMapping {
  id: string;
  name: string;
}

interface Finding {
  category: string;
  code: string;
  status: Status;
  severity: Severity;
  detail: string;
  nist?: NistMapping;
  mitre?: MitreMapping[];
}

// ---------------------------------------------------------------------------
// NIST / MITRE mappings
// ---------------------------------------------------------------------------

const NIST_MAPPINGS: Record<string, NistMapping> = {
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

const MITRE_MAPPINGS: Record<string, MitreMapping[]> = {
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

// ---------------------------------------------------------------------------
// Risk-weighted scoring
// ---------------------------------------------------------------------------

const CATEGORY_WEIGHTS: Record<string, number> = {
  LLM01: 0.25,
  LLM02: 0.10,
  LLM03: 0.05,
  LLM04: 0.10,
  LLM05: 0.15,
  LLM06: 0.15,
  LLM07: 0.05,
  LLM08: 0.05,
  LLM09: 0.05,
  LLM10: 0.05,
};

const SEVERITY_MULTIPLIERS: Record<Severity, number> = {
  critical: 1.00,
  high:     0.70,
  medium:   0.35,
  low:      0.15,
  info:     0.00,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function withMappings(f: Finding): Finding {
  f.nist = NIST_MAPPINGS[f.code];
  f.mitre = MITRE_MAPPINGS[f.code];
  return f;
}

function pass(code: string, category: string, detail: string): Finding {
  return withMappings({ category, code, status: "pass", severity: "info", detail });
}

function fi(flags: string): RegExp {
  return new RegExp(flags, "i");
}

function match(p: RegExp, s: string): boolean {
  return p.test(s);
}

function firstMatch(pairs: [RegExp, string][], prompt: string): [RegExp, string] | null {
  return pairs.find(([p]) => p.test(prompt)) ?? null;
}

// ---------------------------------------------------------------------------
// Detectors — ported 1:1 from scanner.py
// ---------------------------------------------------------------------------

function detectLLM01(prompt: string): Finding {
  const F = "i";
  const hardPatterns: [RegExp, string][] = [
    [/ignore\s+(all\s+)?previous\s+instructions?/i,             "direct override"],
    [/jailbreak/i,                                               "jailbreak attempt"],
    [/bypass\s+(your\s+)?(safety|filter|restriction|instruction)/i, "safety bypass"],
    [/override\s+(your\s+)?instructions?/i,                     "instruction override"],
    [/forget\s+(your|all|everything)/i,                         "memory wipe attempt"],
    [/disregard\s+(your|all|previous)/i,                        "direct override"],
    [/\bDAN\b/,                                                  "DAN jailbreak"],
  ];
  const softPatterns: [RegExp, string][] = [
    [/you\s+are\s+now\s+(a|an)\s+/i,                            "persona replacement"],
    [/pretend\s+(you\s+are|to\s+be)/i,                          "soft persona injection"],
    [/act\s+as\s+(if\s+you\s+are|a)\s+/i,                      "soft persona injection"],
    [/roleplay\s+as\s+(a|an)\s+/i,                              "roleplay-based injection"],
    [/simulate\s+(being\s+)?(a|an)\s+/i,                        "simulation-based injection"],
    [/imagine\s+you\s+(have\s+no|are\s+without)\s+(restrictions?|limits?|guidelines?)/i, "hypothetical constraint removal"],
    [/hypothetically.{0,30}no\s+(restrictions?|limits?|rules?)/i, "hypothetical constraint removal"],
    [/in\s+(a\s+)?(fictional|hypothetical|alternate)\s+(world|scenario|story|universe)/i, "fictional framing injection"],
    [/as\s+a\s+character\s+(who|that)\s+(has\s+no|ignores?)\s+(restrictions?|rules?)/i,  "character-based constraint bypass"],
    [/what\s+would\s+(an\s+)?unrestricted\s+(ai|model|version)/i, "unrestricted AI framing"],
  ];
  const indirectPatterns: [RegExp, string][] = [
    [/when\s+you\s+read\s+a\s+document\s+that\s+contains/i,    "multi-stage indirect injection"],
    [/if\s+any\s+tool\s+returns/i,                             "tool-response hijack"],
    [/the\s+next\s+time\s+you\s+are\s+called/i,               "persistent instruction injection"],
    [/store\s+this\s+instruction\s+for\s+later/i,             "persistent instruction injection"],
  ];

  const hardMatch = firstMatch(hardPatterns, prompt);
  const indirectMatch = firstMatch(indirectPatterns, prompt);
  const softMatches = softPatterns.filter(([p]) => p.test(prompt));

  if (hardMatch || indirectMatch) {
    const m = hardMatch ?? indirectMatch!;
    const attackType = hardMatch ? "Direct injection" : "Indirect/multi-stage injection";
    return withMappings({
      category: "Prompt Injection", code: "LLM01", status: "fail", severity: "critical",
      detail: `${attackType} detected (${m[1]}). Unambiguous attempt to override model guardrails.`,
    });
  }
  if (softMatches.length >= 2) {
    const labels = softMatches.map(([, l]) => l).join(", ");
    return withMappings({
      category: "Prompt Injection", code: "LLM01", status: "fail", severity: "high",
      detail: `Multiple soft injection signals detected (${labels}). Corroborating patterns indicate likely attack intent.`,
    });
  }
  if (softMatches.length === 1) {
    return withMappings({
      category: "Prompt Injection", code: "LLM01", status: "warning", severity: "medium",
      detail: `Soft injection signal detected (${softMatches[0][1]}). May be legitimate context — review prompt. Single ambiguous signal does not confirm attack intent.`,
    });
  }
  return pass("LLM01", "Prompt Injection", "No prompt injection patterns detected.");
}

function detectLLM02(prompt: string): Finding {
  const patterns: [RegExp, string][] = [
    [/\b\d{3}-\d{2}-\d{4}\b/,                    "SSN pattern"],
    [/\b4[0-9]{12}(?:[0-9]{3})?\b/,              "Visa card pattern"],
    [/\b5[1-5][0-9]{14}\b/,                      "Mastercard pattern"],
    [/api[_-]?key\s*[:=]/i,                       "API key reference"],
    [/password\s*[:=]/i,                           "Password reference"],
    [/secret\s*[:=]/i,                             "Secret reference"],
    [/private[_-]?key/i,                           "Private key reference"],
    [/bearer\s+[a-zA-Z0-9._-]{20,}/i,             "Bearer token"],
  ];
  const m = firstMatch(patterns, prompt);
  if (m) {
    return withMappings({
      category: "Sensitive Information Disclosure", code: "LLM02", status: "warning", severity: "medium",
      detail: `Credential detected in prompt (${m[1]}) — intercepted before reaching the model. The credential is now in audit logs. Notify the user and rotate immediately.`,
    });
  }
  return pass("LLM02", "Sensitive Information Disclosure", "No sensitive data patterns detected.");
}

function detectLLM03(prompt: string): Finding {
  const patterns: [RegExp, string][] = [
    [/pip\s+install\s+--?index-url\s+http:\/\//i,         "pip install from HTTP index (no TLS)"],
    [/pip\s+install\s+--?extra-index-url\s+/i,            "pip install from extra-index (supply chain risk)"],
    [/npm\s+install\s+--registry\s+http:\/\//i,            "npm install from HTTP registry (no TLS)"],
    [/load_model\s*\(\s*['"]http:\/\//i,                   "model load from HTTP (no TLS)"],
    [/from_pretrained\s*\(\s*['"](?!microsoft|google|meta|mistralai|openai|anthropic)[a-z0-9_-]{1,10}\//i,
                                                           "Hugging Face model from unverified short-name org"],
    [/hub\.load\s*\(/i,                                    "TF Hub model load (verify source)"],
    [/exec\s*\(\s*requests\.get/i,                         "exec() on downloaded content — remote code execution"],
    [/curl\s+.*\|\s*(bash|sh|python)/i,                    "curl-pipe-shell — supply chain vector"],
    [/wget\s+.*\|\s*(bash|sh|python)/i,                    "wget-pipe-shell — supply chain vector"],
    [/skip[-_]?verify|verify\s*=\s*False|ssl_verify\s*=\s*False/i, "TLS verification disabled"],
    [/--no-?check-?certificate/i,                          "certificate check disabled"],
    [/trust\s+me\s+the\s+(model|package|library)\s+is\s+safe/i, "social engineering — trust override"],
  ];
  const m = firstMatch(patterns, prompt);
  if (m) {
    return withMappings({
      category: "Supply Chain Vulnerabilities", code: "LLM03", status: "fail", severity: "high",
      detail: `Supply chain risk detected: ${m[1]}. Prompt references potentially untrusted model/package sources.`,
    });
  }
  return pass("LLM03", "Supply Chain Vulnerabilities", "No supply chain vulnerability patterns detected. Note: static analysis cannot verify model provenance — dynamic testing recommended.");
}

function detectLLM04(prompt: string): Finding {
  const patterns: [RegExp, string][] = [
    [/ignore\s+the\s+retrieved\s+context/i,                    "retrieved context suppression"],
    [/the\s+real\s+answer\s+is\s+not\s+in\s+the\s+documents/i, "document authority bypass"],
    [/search\s+for\s+documents?\s+that\s+say/i,                "retrieval steering"],
    [/only\s+use\s+documents?\s+from/i,                        "source restriction manipulation"],
    [/when\s+this\s+document\s+is\s+(loaded|retrieved|read)/i, "document-borne payload trigger"],
    [/embedded\s+instruction\s+in\s+(the\s+)?(document|file|page)/i, "embedded instruction delivery"],
    [/payload\s+(in|inside|within)\s+(the\s+)?(document|file|pdf|page)/i, "document payload delivery"],
  ];
  const m = firstMatch(patterns, prompt);
  if (m) {
    return withMappings({
      category: "Data and Model Poisoning", code: "LLM04", status: "fail", severity: "high",
      detail: `RAG poisoning pattern detected: ${m[1]}. Prompt attempts to corrupt or manipulate retrieval-augmented context.`,
    });
  }
  return pass("LLM04", "Data and Model Poisoning", "No RAG poisoning or context injection patterns detected.");
}

function detectLLM05(prompt: string): Finding {
  const xssPatterns: [RegExp, string][] = [
    [/<script\b/i,              "script tag injection"],
    [/javascript:/i,            "javascript: URI"],
    [/on\w+\s*=\s*["']/i,      "inline event handler"],
    [/\beval\s*\(/i,            "eval() call"],
    [/innerHTML\s*=/i,          "innerHTML assignment"],
  ];
  const codePatterns: [RegExp, string][] = [
    [/exec\s*\(\s*(base64|zlib|decompress|decode)/i,       "exec() on encoded payload — packed malware pattern"],
    [/base64[._]b64decode[\s\S]*exec/i,                     "base64 decode + exec — fileless payload pattern"],
    [/zlib\.decompress[\s\S]*base64/i,                      "zlib+base64 decompression — packer combo"],
    [/importlib[\s\S]*_bootstrap[\s\S]*exec/i,              "importlib bootstrap exec — AV evasion technique"],
    [/powershell.*-enc(odedcommand)?\s+[A-Za-z0-9+/]{20,}/i, "PowerShell encoded command — LOtL technique"],
    [/certutil.*-urlcache.*-f/i,                            "certutil file download — LOtL dropper"],
    [/load_config[\s\S]*exec\s*\(/i,                        "config loader masking exec() — obfuscated dropper"],
    [/subprocess\.(call|run|Popen).*shell\s*=\s*True/i,    "shell=True subprocess — command injection risk"],
    [/os\.system\s*\(|os\.popen\s*\(/i,                    "os.system/popen — arbitrary command execution"],
    [/__import__\s*\(\s*['"]os['"]\s*\)/i,                 "__import__('os') — obfuscated OS access"],
  ];

  const codeMatch = firstMatch(codePatterns, prompt);
  if (codeMatch) {
    return withMappings({
      category: "Improper Output Handling", code: "LLM05", status: "fail", severity: "critical",
      detail: `Malicious code output pattern detected: ${codeMatch[1]}. LLM may be generating or assisting with obfuscated/packed malware.`,
    });
  }
  const xssMatch = firstMatch(xssPatterns, prompt);
  if (xssMatch) {
    return withMappings({
      category: "Improper Output Handling", code: "LLM05", status: "warning", severity: "medium",
      detail: `Unsafe output pattern detected: ${xssMatch[1]}. May trigger XSS or injection in downstream rendering.`,
    });
  }
  return pass("LLM05", "Improper Output Handling", "No unsafe output handling patterns detected.");
}

function detectLLM06(prompt: string): Finding {
  const destructivePatterns: RegExp[] = [
    /\bdelete\s+(all|every|production)/i,
    /deploy\s+to\s+production/i,
    /modify\s+production/i,
    /drop\s+(table|database|db)/i,
    /rm\s+-rf/i,
    /shell_exec|system\(/i,
    /call\s+this\s+tool\s+with\s+admin/i,
    /use\s+the\s+file\s+(system\s+)?tool\s+to/i,
    /execute\s+this\s+mcp\s+tool/i,
    /tell\s+the\s+other\s+agent\s+to/i,
    /instruct\s+the\s+sub-?agent/i,
    /relay\s+this\s+to\s+the\s+orchestrator/i,
    /add\s+this\s+to\s+your\s+memory/i,
    /remember\s+for\s+all\s+future/i,
    /update\s+your\s+persistent\s+memory/i,
    /connect\s+to\s+mcp\s+server/i,
    /list\s+available\s+mcp\s+tools/i,
    /invoke\s+mcp/i,
  ];
  const operationalPatterns: RegExp[] = [
    /execute\s+(command|script|code|shell)/i,
    /run\s+(this\s+)?(command|script|code)/i,
    /\bdelete\s+(the|this)\s+/i,
    /sudo\s+/i,
  ];

  if (destructivePatterns.some(p => p.test(prompt))) {
    return withMappings({
      category: "Excessive Agency", code: "LLM06", status: "fail", severity: "high",
      detail: "Prompt requests destructive or high-privilege actions — clear excessive agency risk.",
    });
  }
  if (operationalPatterns.some(p => p.test(prompt))) {
    return withMappings({
      category: "Excessive Agency", code: "LLM06", status: "warning", severity: "medium",
      detail: "Prompt contains operational action language (execute/run/delete/sudo). Likely legitimate DevOps context — verify intent before granting agentic permissions.",
    });
  }
  return pass("LLM06", "Excessive Agency", "No excessive agency patterns detected.");
}

function detectLLM07(prompt: string): Finding {
  const patterns: RegExp[] = [
    /reveal\s+your\s+system\s+prompt/i,
    /what\s+(are\s+)?your\s+(instructions|directives|rules|constraints)/i,
    /ignore\s+all\s+previous/i,
    /print\s+your\s+(initial\s+)?prompt/i,
    /show\s+me\s+your\s+(system|initial)\s+prompt/i,
    /repeat\s+(everything|all|the)\s+above/i,
  ];
  if (patterns.some(p => p.test(prompt))) {
    return withMappings({
      category: "System Prompt Leakage", code: "LLM07", status: "warning", severity: "medium",
      detail: "Prompt attempts to extract system prompt or internal instructions.",
    });
  }
  return pass("LLM07", "System Prompt Leakage", "No system prompt extraction attempts detected.");
}

function detectLLM08(prompt: string): Finding {
  const patterns: [RegExp, string][] = [
    [/inject\s+(into|text\s+into)\s+(the\s+)?(vector|embedding|rag|retrieval)/i, "vector store injection"],
    [/store\s+(this|the\s+following)\s+in\s+(the\s+)?(vector|embedding)/i,       "direct vector store write attempt"],
    [/make\s+(this|the\s+following)\s+document\s+appear\s+(at\s+top|first|most\s+relevant)/i, "ranking manipulation"],
    [/when\s+retrieved\s+from\s+(the\s+)?(vector|embedding|knowledge)/i,         "retrieval-triggered payload"],
    [/similar\s+to\s+.*password|similar\s+to\s+.*secret|similar\s+to\s+.*token/i, "semantic similarity probe for secrets"],
    [/find\s+embeddings?\s+(similar\s+to|near|close\s+to)\s+/i,                  "embedding similarity probe"],
    [/poison\s+(the\s+)?(vector|embedding|knowledge\s+base|rag)/i,               "explicit vector poisoning"],
    [/corrupt\s+(the\s+)?(vector|embedding|index|knowledge)/i,                   "vector index corruption"],
    [/modify\s+(the\s+)?(embedding|vector\s+store|knowledge\s+base)/i,           "vector store tampering"],
    [/make\s+the\s+(model|llm|ai)\s+think\s+(this\s+is\s+)?similar/i,            "semantic deception"],
    [/(look|appear|seem)\s+semantically\s+(similar|identical)\s+to/i,            "semantic similarity spoofing"],
  ];
  const m = firstMatch(patterns, prompt);
  if (m) {
    return withMappings({
      category: "Vector and Embedding Weaknesses", code: "LLM08", status: "fail", severity: "high",
      detail: `Vector/embedding attack pattern detected: ${m[1]}. Prompt may attempt to manipulate retrieval-augmented generation infrastructure.`,
    });
  }
  return pass("LLM08", "Vector and Embedding Weaknesses", "No vector or embedding attack patterns detected.");
}

function detectLLM09(prompt: string): Finding {
  const patterns: [RegExp, string][] = [
    [/make\s+up\s+(a|some|fake|plausible)\s+(citation|reference|source|study|report)/i, "fabricate citation"],
    [/invent\s+(a|some)\s+(fact|statistic|study|report|quote)/i,                       "invent facts"],
    [/write\s+(a|an)\s+fake\s+(news|article|press\s+release|report)/i,                 "fake news generation"],
    [/generate\s+(misinformation|disinformation|propaganda|fake\s+content)/i,           "explicit misinformation request"],
    [/pretend\s+(you|the\s+data|the\s+study)\s+shows/i,                                "false data fabrication"],
    [/(say|claim|state)\s+that\s+.{0,50}(even\s+if\s+(it's\s+not|false|untrue|incorrect))/i, "deliberately false statement"],
    [/hallucinate\s+(some|a|more)/i,                                                    "explicit hallucination trigger"],
    [/cite\s+(a\s+|some\s+)?non-?existent\s+(study|paper|report|source)/i,             "fabricate nonexistent citation"],
    [/as\s+(the\s+)?(cdc|fda|who|nih|nist|cisa|white\s+house)\s+(says?|reports?|confirms?|warns?)/i, "government authority impersonation"],
    [/write\s+as\s+if\s+(you\s+are|from)\s+(cnn|bbc|reuters|ap|new\s+york\s+times)/i,               "news outlet impersonation"],
    [/on\s+behalf\s+of\s+(the\s+president|congress|parliament|government)/i,                         "government impersonation"],
  ];
  const m = firstMatch(patterns, prompt);
  if (m) {
    return withMappings({
      category: "Misinformation", code: "LLM09", status: "fail", severity: "high",
      detail: `Misinformation generation request detected: ${m[1]}. Prompt attempts to produce or spread deliberately false information.`,
    });
  }
  return pass("LLM09", "Misinformation", "No misinformation or fabrication patterns detected.");
}

function detectLLM10(prompt: string): Finding {
  const patterns: [RegExp, string][] = [
    [/repeat\s+(the\s+following|this)\s+(\d{3,}|infinitely|forever|endlessly)/i, "repetition bomb"],
    [/write\s+(\d{4,}|ten\s+thousand|one\s+hundred\s+thousand)\s+(words|tokens|characters)/i, "token flooding"],
    [/loop\s+forever|while\s+True|while\s+1\s*:/i,                               "infinite loop injection"],
    [/keep\s+going\s+until\s+(you\s+)?(run\s+out\s+of|hit|reach)\s+(token|context|memory|limit)/i, "resource exhaustion trigger"],
    [/do\s+not\s+stop\s+until\s+you\s+(run\s+out|exhaust|fill|overflow)/i,       "context overflow attempt"],
    [/output\s+(\d{5,}|millions?\s+of)\s+(tokens?|words?|characters?)/i,         "large output flooding"],
    [/(factorial|permutation|combinations?)\s+of\s+(\d{3,}|\d+!)/i,              "computational complexity bomb"],
    [/(expand|enumerate|list)\s+(all\s+)?possible\s+(combinations?|permutations?)\s+of/i, "combinatorial explosion"],
    [/recursively\s+(call|invoke|expand)\s+(yourself|itself|this)\s+(forever|endlessly|infinitely)/i, "recursive self-call bomb"],
    [/fill\s+(your\s+entire\s+)?(context|context\s+window|memory)\s+with/i,      "context window flooding"],
  ];
  const m = firstMatch(patterns, prompt);
  if (m) {
    return withMappings({
      category: "Unbounded Consumption", code: "LLM10", status: "fail", severity: "medium",
      detail: `Resource exhaustion pattern detected: ${m[1]}. Prompt may trigger unbounded token generation or computational DoS.`,
    });
  }
  return pass("LLM10", "Unbounded Consumption", "No unbounded consumption patterns detected.");
}

// ---------------------------------------------------------------------------
// Scan runner
// ---------------------------------------------------------------------------

function runScan(prompt: string): { score: number; findings: Finding[] } {
  const findings: Finding[] = [
    detectLLM01(prompt),
    detectLLM02(prompt),
    detectLLM03(prompt),
    detectLLM04(prompt),
    detectLLM05(prompt),
    detectLLM06(prompt),
    detectLLM07(prompt),
    detectLLM08(prompt),
    detectLLM09(prompt),
    detectLLM10(prompt),
  ];

  let totalDeduction = 0;
  for (const f of findings) {
    if (f.status !== "pass") {
      const weight = CATEGORY_WEIGHTS[f.code] ?? 0.05;
      const multiplier = SEVERITY_MULTIPLIERS[f.severity] ?? 0;
      totalDeduction += weight * 100 * multiplier;
    }
  }

  const score = Math.max(0, Math.round(100 - totalDeduction));
  return { score, findings };
}

// ---------------------------------------------------------------------------
// Route handler
// ---------------------------------------------------------------------------

export async function POST(req: NextRequest) {
  let body: { prompt?: string; model?: string; scenario?: string; mode?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const prompt = (body.prompt ?? "").trim();
  if (!prompt) {
    return NextResponse.json({ error: "prompt is required" }, { status: 400 });
  }

  const t0 = Date.now();
  const { score, findings } = runScan(prompt);
  const latency_ms = Date.now() - t0;

  return NextResponse.json({
    scan_id: randomUUID(),
    score,
    findings,
    model: body.model ?? "claude-sonnet-4-6",
    scenario: body.scenario ?? null,
    prompt_length: prompt.length,
    categories_checked: findings.length,
    latency_ms,
    timestamp: new Date().toISOString(),
  });
}
