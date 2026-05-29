// AISeal F4 — IRIS request hardening.
//
// Shared guard library used by /api/iris and /api/iris/chat to close the F4
// audit gap (open Anthropic-backed routes → $345K/day drain risk worst case).
//
// Four layers of defense:
//   1. Origin / Referer must match AISEAL_ALLOWED_ORIGINS (default: aiseal.ai).
//      Third-party sites can't embed the IRIS chat widget and proxy through
//      AISeal's Anthropic key.
//   2. Per-IP rate limit (in-memory, tight: 10/hr for /iris, 30/hr for chat).
//   3. Global daily cap (Supabase-backed) — survives Railway cold starts and
//      spans replicas. Hard ceiling on total Anthropic spend regardless of IPs.
//   4. IP extraction uses the LAST x-forwarded-for entry (not the first), so
//      a spoofed first entry can't bypass the per-IP limiter.
//
// The Anthropic console $100/day spend cap remains as a final backstop.

import { createHash } from "node:crypto";
import { rateLimit } from "@/app/lib/rate-limit";
import { supabaseAdmin } from "./supabase/server";

export type IrisRoute = "iris" | "iris_chat";

export interface GuardConfig {
  route: IrisRoute;
  perIpPerHour: number;        // tight per-IP cap
  globalDailyCap: number;      // hard ceiling
}

export const IRIS_GUARD: Record<IrisRoute, GuardConfig> = {
  iris:      { route: "iris",      perIpPerHour: 10, globalDailyCap: 200 },
  iris_chat: { route: "iris_chat", perIpPerHour: 30, globalDailyCap: 500 },
};

const DEFAULT_ALLOWED_ORIGINS = ["aiseal.ai", "www.aiseal.ai"];

function allowedOrigins(): string[] {
  const env = process.env.AISEAL_ALLOWED_ORIGINS;
  if (!env) return DEFAULT_ALLOWED_ORIGINS;
  return env.split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
}

function toHost(s: string | null | undefined): string | null {
  if (!s) return null;
  try {
    return new URL(s.startsWith("http") ? s : `https://${s}`).hostname.toLowerCase();
  } catch {
    return s.toLowerCase().trim();
  }
}

export function ipFromHeaders(req: Request): string {
  // Use the LAST x-forwarded-for entry (Railway/proxy-set). First entry is
  // client-controlled and spoofable; using it would let an attacker bypass
  // the per-IP rate limit by injecting unique fake IPs.
  const xff = req.headers.get("x-forwarded-for");
  if (xff) {
    const parts = xff.split(",").map((p) => p.trim()).filter(Boolean);
    if (parts.length > 0) return parts[parts.length - 1];
  }
  return req.headers.get("x-real-ip")?.trim() ?? "unknown";
}

export function hashIp(ip: string): string {
  return createHash("sha256").update(ip).digest("hex").slice(0, 32);
}

/** Permissive CORS preflight — only allows POST from approved origins. */
export function preflight(req: Request): Response | null {
  if (req.method !== "OPTIONS") return null;
  const origin = req.headers.get("origin");
  const host = toHost(origin);
  const allowed = allowedOrigins();
  const isAllowed = host !== null && allowed.includes(host);
  return new Response(null, {
    status: isAllowed ? 204 : 403,
    headers: isAllowed
      ? {
          "access-control-allow-origin": origin ?? "*",
          "access-control-allow-methods": "POST, OPTIONS",
          "access-control-allow-headers": "content-type",
          "access-control-max-age": "600",
          vary: "Origin",
        }
      : { "content-type": "text/plain" },
  });
}

export type GuardResult =
  | { ok: true; ip_hash: string; origin: string | null; user_agent: string | null }
  | {
      ok: false;
      status: number;
      reason: "rate_limit_ip" | "daily_cap" | "origin_blocked";
      message: string;
      ip_hash: string;
      origin: string | null;
      user_agent: string | null;
    };

/**
 * Run the full 3-layer guard pre-flight before any Anthropic call.
 * Logs every blocked attempt to iris_usage so we can analyze abuse patterns.
 */
export async function runGuard(req: Request, route: IrisRoute): Promise<GuardResult> {
  const cfg = IRIS_GUARD[route];
  const ip = ipFromHeaders(req);
  const ip_hash = hashIp(ip);
  const origin = req.headers.get("origin");
  const referer = req.headers.get("referer");
  const user_agent = req.headers.get("user-agent")?.slice(0, 300) ?? null;

  // 1. Origin / Referer guard
  const callerHost = toHost(origin) ?? toHost(referer);
  const allowed = allowedOrigins();
  // Empty Origin is acceptable for same-origin server-side fetches from inside
  // the AISeal Next app itself (Next route handlers don't set Origin). Block
  // only when an EXPLICIT Origin is present and it's not on the allow list.
  if (callerHost !== null && !allowed.includes(callerHost)) {
    await logBlocked({ route, ip_hash, origin, user_agent, reason: "origin_blocked" });
    return {
      ok: false,
      status: 403,
      reason: "origin_blocked",
      message: `Origin ${callerHost} is not on the AISeal allowed-origins list. IRIS endpoints are only callable from aiseal.ai.`,
      ip_hash,
      origin,
      user_agent,
    };
  }

  // 2. Per-IP rate limit (in-memory, tight per-hour cap)
  const { ok: ipOk } = rateLimit(`${route}:${ip}`, {
    maxRequests: cfg.perIpPerHour,
    windowMs: 60 * 60 * 1000,
  });
  if (!ipOk) {
    await logBlocked({ route, ip_hash, origin, user_agent, reason: "rate_limit_ip" });
    return {
      ok: false,
      status: 429,
      reason: "rate_limit_ip",
      message: `Per-IP rate limit exceeded (${cfg.perIpPerHour}/hr). Try again later.`,
      ip_hash,
      origin,
      user_agent,
    };
  }

  // 3. Global daily cap (Supabase) — survives cold starts + spans replicas
  try {
    const admin = supabaseAdmin();
    const dayStart = new Date();
    dayStart.setHours(0, 0, 0, 0);
    const { count } = await admin
      .from("iris_usage")
      .select("*", { count: "exact", head: true })
      .eq("route", route)
      .eq("ok", true)
      .gte("created_at", dayStart.toISOString());
    if ((count ?? 0) >= cfg.globalDailyCap) {
      await logBlocked({ route, ip_hash, origin, user_agent, reason: "daily_cap" });
      return {
        ok: false,
        status: 429,
        reason: "daily_cap",
        message: `IRIS daily capacity reached for ${route} (${cfg.globalDailyCap}/day). Try again tomorrow.`,
        ip_hash,
        origin,
        user_agent,
      };
    }
  } catch (e) {
    // Supabase outage shouldn't take down /iris entirely. Log + fail open
    // (the per-IP limiter still protects against runaway abuse).
    console.error("[iris-guard] daily-cap check failed", e);
  }

  return { ok: true, ip_hash, origin, user_agent };
}

interface SuccessLog {
  route: IrisRoute;
  ip_hash: string;
  origin: string | null;
  user_agent: string | null;
  model: string;
  duration_ms: number;
  prompt_chars: number;
  reply_chars: number;
}

export async function logSuccess(args: SuccessLog): Promise<void> {
  try {
    await supabaseAdmin().from("iris_usage").insert({
      route: args.route,
      ip_hash: args.ip_hash,
      origin: args.origin,
      user_agent: args.user_agent,
      ok: true,
      model: args.model,
      duration_ms: args.duration_ms,
      prompt_chars: args.prompt_chars,
      reply_chars: args.reply_chars,
    });
  } catch (e) {
    console.error("[iris-guard] success log failed", e);
  }
}

interface BlockedLog {
  route: IrisRoute;
  ip_hash: string;
  origin: string | null;
  user_agent: string | null;
  reason: "rate_limit_ip" | "daily_cap" | "origin_blocked" | "validation" | "llm_error";
}

export async function logBlocked(args: BlockedLog): Promise<void> {
  try {
    await supabaseAdmin().from("iris_usage").insert({
      route: args.route,
      ip_hash: args.ip_hash,
      origin: args.origin,
      user_agent: args.user_agent,
      ok: false,
      blocked_reason: args.reason,
    });
  } catch (e) {
    console.error("[iris-guard] blocked log failed", e);
  }
}

/** Apply CORS headers to a successful response. */
export function withCors(res: Response, req: Request): Response {
  const origin = req.headers.get("origin");
  const host = toHost(origin);
  const allowed = allowedOrigins();
  if (host !== null && allowed.includes(host) && origin) {
    res.headers.set("access-control-allow-origin", origin);
    res.headers.set("vary", "Origin");
  }
  return res;
}
