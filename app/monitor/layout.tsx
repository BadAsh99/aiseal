import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "AISeal Monitor — Runtime LLM Security",
  description: "Real-time behavioral monitoring for production LLM traffic. Prompt injection alerts, anomaly detection, and full audit logging.",
};

export default function MonitorLayout({ children }: { children: React.ReactNode }) {
  return <>{children}</>;
}
