import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "TrustScan — AISeal",
  description: "OWASP LLM Top 10 vulnerability scanner with TrustScore. Test your AI endpoints against prompt injection, data exfiltration, and 8 more attack categories.",
};

export default function ScanLayout({ children }: { children: React.ReactNode }) {
  return <>{children}</>;
}
