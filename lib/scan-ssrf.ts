// SSRF guard for the live endpoint scanner.
//
// /api/scan/live makes outbound HTTPS requests to vendor-supplied URLs to
// red-team their production AI endpoint. That is a powerful capability and a
// classic SSRF vector — without guards, an attacker could point us at internal
// services (cloud metadata, intranet endpoints, RFC1918, localhost) and use
// AISeal as a proxy.
//
// Layers:
//   1. HTTPS only — refuse http://, file://, gopher://, anything else.
//   2. Block obvious internal hostnames (localhost, *.local, *.internal).
//   3. Block private + reserved IP ranges (RFC1918, link-local, ULA, loopback).
//   4. Block known cloud-metadata endpoints.
//   5. (Future) Resolve hostname to IP at request time and re-check (defeats
//      DNS rebinding). Not in this MVP — flagged as a hardening follow-up.
//
// The vendor must also register a vendor_domain at cert application time
// (lib/registry.ts), and the scanner constrains the endpoint host to that
// domain. That's a stronger guard than SSRF blocklists — it means we only
// ever scan the host the vendor told us about.

export type SsrfReason =
  | "ok"
  | "invalid_url"
  | "wrong_protocol"
  | "internal_hostname"
  | "private_ip"
  | "metadata_endpoint"
  | "domain_mismatch";

export interface SsrfResult {
  ok: boolean;
  reason: SsrfReason;
  detail?: string;
  host?: string;
}

const PRIVATE_IPV4_RANGES: Array<(host: string) => boolean> = [
  (h) => /^127\./.test(h),                                                 // loopback
  (h) => /^10\./.test(h),                                                  // RFC1918
  (h) => /^192\.168\./.test(h),                                            // RFC1918
  (h) => /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(h),                         // RFC1918
  (h) => /^169\.254\./.test(h),                                            // link-local (AWS/Azure metadata)
  (h) => /^0\.0\.0\.0$/.test(h),
  (h) => /^100\.6[4-9]\./.test(h) || /^100\.[7-9][0-9]\./.test(h) || /^100\.1[0-1][0-9]\./.test(h) || /^100\.12[0-7]\./.test(h),  // CGNAT 100.64.0.0/10
];

const PRIVATE_IPV6_PATTERNS: RegExp[] = [
  /^::1$/i,                          // loopback
  /^fc[0-9a-f]{2}:/i,                // ULA fc00::/7
  /^fd[0-9a-f]{2}:/i,                // ULA fc00::/7
  /^fe80:/i,                         // link-local fe80::/10
];

const INTERNAL_HOST_SUFFIXES = [
  ".local",
  ".internal",
  ".intranet",
  ".localdomain",
];

const INTERNAL_HOSTNAMES = new Set([
  "localhost",
  "metadata.google.internal",      // GCP metadata
  "metadata.azure.com",            // Azure metadata
  "metadata.azure.us",
  "metadata",                      // some k8s clusters
  "host.docker.internal",
  "kubernetes.default.svc",
]);

/** True if the URL targets a host that's clearly NOT a public production endpoint. */
export function checkUrl(rawUrl: string, vendorDomain: string | null): SsrfResult {
  let u: URL;
  try {
    u = new URL(rawUrl);
  } catch {
    return { ok: false, reason: "invalid_url", detail: "URL did not parse" };
  }

  if (u.protocol !== "https:") {
    return { ok: false, reason: "wrong_protocol", detail: `Got ${u.protocol}, only https: allowed` };
  }

  const host = u.hostname.toLowerCase();

  if (INTERNAL_HOSTNAMES.has(host)) {
    return { ok: false, reason: "metadata_endpoint", host, detail: `${host} is a known internal/metadata endpoint` };
  }

  for (const suffix of INTERNAL_HOST_SUFFIXES) {
    if (host.endsWith(suffix)) {
      return { ok: false, reason: "internal_hostname", host, detail: `Host ends with ${suffix}` };
    }
  }

  // Strip brackets from IPv6 literal
  const ipv6Candidate = host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
  for (const re of PRIVATE_IPV6_PATTERNS) {
    if (re.test(ipv6Candidate)) {
      return { ok: false, reason: "private_ip", host, detail: "IPv6 private/reserved range" };
    }
  }

  // IPv4 literal check
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) {
    for (const fn of PRIVATE_IPV4_RANGES) {
      if (fn(host)) return { ok: false, reason: "private_ip", host, detail: "IPv4 private/reserved range" };
    }
  }

  // Vendor domain enforcement — the strongest guard.
  // Host must equal vendor_domain OR be a subdomain of it.
  if (vendorDomain) {
    const vd = vendorDomain.toLowerCase().trim();
    if (host !== vd && !host.endsWith(`.${vd}`)) {
      return {
        ok: false,
        reason: "domain_mismatch",
        host,
        detail: `Host ${host} is not ${vd} or a subdomain of it`,
      };
    }
  }

  return { ok: true, reason: "ok", host };
}
