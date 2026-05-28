"use client";

// AISeal F1+F2 — embed snippet pointing at the SELF-HOSTED HMAC-signed badge.
// Was previously shields.io PNG (forgeable, free-ride). Now points at
// /api/badges/{cert_id}.svg, which embeds an HMAC signature verifiable via
// /api/verify/{cert_id}. The displayed code and the copied code are identical.

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

  const badgeUrl = `https://aiseal.ai/api/badges/${certId}.svg`;
  const registryUrl = `https://aiseal.ai/registry/${vendorId}`;
  const altText = `AISeal ${tier} Certified — TrustScore ${score}/100`;

  const embedHtml = `<a href="${registryUrl}" target="_blank" rel="noopener noreferrer" title="${altText}">
  <img
    src="${badgeUrl}"
    alt="${altText}"
    width="240"
    height="60"
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
          <span style={{ color: "#fca5a5" }}>&quot;{registryUrl}&quot;</span>
          {` `}
          <span style={{ color: "#86efac" }}>target</span>
          <span style={{ color: "#9ca3af" }}>=</span>
          <span style={{ color: "#fca5a5" }}>&quot;_blank&quot;</span>
          {`\n  `}
          <span style={{ color: "#86efac" }}>title</span>
          <span style={{ color: "#9ca3af" }}>=</span>
          <span style={{ color: "#fca5a5" }}>&quot;{altText}&quot;</span>
          <span style={{ color: "#7dd3fc" }}>&gt;</span>
          {`\n  `}
          <span style={{ color: "#7dd3fc" }}>&lt;img</span>
          {`\n    `}
          <span style={{ color: "#86efac" }}>src</span>
          <span style={{ color: "#9ca3af" }}>=</span>
          <span style={{ color: "#fca5a5" }}>&quot;{badgeUrl}&quot;</span>
          {`\n    `}
          <span style={{ color: "#86efac" }}>alt</span>
          <span style={{ color: "#9ca3af" }}>=</span>
          <span style={{ color: "#fca5a5" }}>&quot;{altText}&quot;</span>
          {`\n    `}
          <span style={{ color: "#86efac" }}>width</span>
          <span style={{ color: "#9ca3af" }}>=</span>
          <span style={{ color: "#fca5a5" }}>&quot;240&quot;</span>
          {` `}
          <span style={{ color: "#86efac" }}>height</span>
          <span style={{ color: "#9ca3af" }}>=</span>
          <span style={{ color: "#fca5a5" }}>&quot;60&quot;</span>
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

      <p className="text-xs mt-3 leading-relaxed" style={{ color: "var(--text-muted)" }}>
        The badge is HMAC-signed and self-hosted on aiseal.ai. Validators can cross-check it
        against{" "}
        <span className="font-mono" style={{ color: "var(--text-secondary)" }}>
          /api/verify/{certId}
        </span>{" "}
        — if the badge was tampered with, signatures won&apos;t match.
      </p>
    </div>
  );
}
