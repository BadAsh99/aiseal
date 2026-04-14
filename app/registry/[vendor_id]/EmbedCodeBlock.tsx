"use client";

import { useState } from "react";
import type { CertTier } from "../../../lib/registry";

interface EmbedCodeBlockProps {
  certId: string;
  vendorId: string;
  tier: CertTier;
  score: number;
}

export default function EmbedCodeBlock({ certId, vendorId, tier, score }: EmbedCodeBlockProps) {
  const [copied, setCopied] = useState(false);

  const tierColor = tier === "ACF-3" ? "%23d4a017" : tier === "ACF-2" ? "%230080ff" : "%2300c853";
  const shieldSvg = `https://img.shields.io/badge/AISeal-${tier}%20%7C%20${score}%2F100-${tierColor.replace("%23","")}?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZD0iTTEyIDJMMyA3djZjMCA1LjU1IDMuODQgMTAuNzQgOSAxMiA1LjE2LTEuMjYgOS02LjQ1IDktMTJWN2wtOS01eiIgZmlsbD0id2hpdGUiLz48L3N2Zz4=`;
  const embedHtml = `<a href="https://aiseal.ai/registry/${vendorId}" target="_blank" rel="noopener noreferrer" title="AISeal ${tier} Certificate — TrustScore ${score}/100">
  <img
    src="${shieldSvg}"
    alt="AISeal ${tier} Certified — TrustScore ${score}"
    height="28"
    style="border: none;"
  />
</a>`;

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(embedHtml);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      const ta = document.createElement("textarea");
      ta.value = embedHtml;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      document.body.removeChild(ta);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="relative">
      <div
        className="rounded-lg p-4 font-mono text-xs leading-relaxed overflow-x-auto"
        style={{
          background: "var(--bg-elevated, #0d0d0d)",
          border: "1px solid var(--border-mid)",
          color: "#9ca3af",
        }}
      >
        <pre style={{ margin: 0, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
          <span style={{ color: "#7dd3fc" }}>&lt;a</span>
          {` `}
          <span style={{ color: "#86efac" }}>href</span>
          <span style={{ color: "#9ca3af" }}>=</span>
          <span style={{ color: "#fca5a5" }}>&quot;https://aiseal.ai/registry/{vendorId}&quot;</span>
          {` `}
          <span style={{ color: "#86efac" }}>target</span>
          <span style={{ color: "#9ca3af" }}>=</span>
          <span style={{ color: "#fca5a5" }}>&quot;_blank&quot;</span>
          {`\n  `}
          <span style={{ color: "#86efac" }}>title</span>
          <span style={{ color: "#9ca3af" }}>=</span>
          <span style={{ color: "#fca5a5" }}>&quot;AISeal {tier} — TrustScore {score}/100&quot;</span>
          <span style={{ color: "#7dd3fc" }}>&gt;</span>
          {`\n  `}
          <span style={{ color: "#7dd3fc" }}>&lt;img</span>
          {`\n    `}
          <span style={{ color: "#86efac" }}>src</span>
          <span style={{ color: "#9ca3af" }}>=</span>
          <span style={{ color: "#fca5a5" }}>&quot;https://aiseal.ai/badges/{certId}.svg&quot;</span>
          {`\n    `}
          <span style={{ color: "#86efac" }}>alt</span>
          <span style={{ color: "#9ca3af" }}>=</span>
          <span style={{ color: "#fca5a5" }}>&quot;AISeal {tier} Certified&quot;</span>
          {`\n    `}
          <span style={{ color: "#86efac" }}>width</span>
          <span style={{ color: "#9ca3af" }}>=</span>
          <span style={{ color: "#fca5a5" }}>&quot;160&quot;</span>
          {` `}
          <span style={{ color: "#86efac" }}>height</span>
          <span style={{ color: "#9ca3af" }}>=</span>
          <span style={{ color: "#fca5a5" }}>&quot;160&quot;</span>
          {` `}
          <span style={{ color: "#7dd3fc" }}>/&gt;</span>
          {`\n`}
          <span style={{ color: "#7dd3fc" }}>&lt;/a&gt;</span>
        </pre>
      </div>

      <button
        onClick={handleCopy}
        className="absolute top-2.5 right-2.5 px-3 py-1.5 rounded-md text-xs font-semibold flex items-center gap-1.5 transition-all"
        style={{
          background: copied ? "rgba(0,200,83,0.15)" : "rgba(255,255,255,0.06)",
          color: copied ? "#00c853" : "var(--text-secondary)",
          border: `1px solid ${copied ? "rgba(0,200,83,0.3)" : "var(--border-mid)"}`,
        }}
      >
        {copied ? (
          <>
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none">
              <path d="M5 12L10 17L19 7" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
            Copied
          </>
        ) : (
          <>
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none">
              <rect x="9" y="9" width="11" height="11" rx="2" stroke="currentColor" strokeWidth="1.5" />
              <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1" stroke="currentColor" strokeWidth="1.5" />
            </svg>
            Copy HTML
          </>
        )}
      </button>
    </div>
  );
}
