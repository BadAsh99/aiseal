import { describe, it, expect } from "vitest";
import { checkUrl } from "@/lib/scan-ssrf";

// SSRF guard: the scanner must refuse to be pointed at internal/private targets,
// or it becomes a server-side request proxy. Blocking is the security property.
describe("scan-ssrf · scanner-abuse protection", () => {
  it("allows a normal external https target", () => {
    expect(checkUrl("https://example.com/api", "example.com").ok).toBe(true);
  });

  it("blocks non-https", () => {
    const r = checkUrl("http://example.com", null);
    expect(r.ok).toBe(false);
    expect(r.reason).toBe("wrong_protocol");
  });

  it("blocks loopback (127.0.0.1)", () => {
    expect(checkUrl("https://127.0.0.1/x", null).ok).toBe(false);
  });

  it("blocks a private IP (10.x)", () => {
    expect(checkUrl("https://10.0.0.1/", null).ok).toBe(false);
  });

  it("blocks the cloud metadata endpoint (169.254.169.254)", () => {
    expect(checkUrl("https://169.254.169.254/latest/meta-data", null).ok).toBe(false);
  });

  it("rejects an unparseable URL", () => {
    const r = checkUrl("not a url", null);
    expect(r.ok).toBe(false);
    expect(r.reason).toBe("invalid_url");
  });
});
