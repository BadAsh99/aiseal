// AISeal — cert_telemetry weekly re-scan cron.
//
// Closes the v2.1 Validation gap: "ACF-3 maintains a security posture" was
// marketing copy backed by zero telemetry. This endpoint runs the live scan
// machinery against every active certified vendor and persists the result to
// cert_telemetry so /registry/{vendor_id} can render a posture timeline.
//
// Trigger:
//   Hit this endpoint weekly (Mondays 6am UTC suggested) from any scheduler.
//   Options that work on Railway today:
//     1. Railway cron service: cron `0 6 * * 1` running `curl -fsS -H "x-cron-secret: $CRON_SECRET" https://aiseal.ai/api/cron/cert-telemetry`
//     2. GitHub Actions schedule: same curl from a workflow with cron
//     3. cron-job.org / EasyCron: free external scheduler
//   No new dependency or process. The route is the cron unit.
//
// Auth:
//   Requires header `x-cron-secret: $CRON_SECRET`. Without it: 401.
//   CRON_SECRET must be set in Railway env. Generate via `openssl rand -hex 32`.
//
// Target discovery:
//   `CERT_RESCAN_TARGETS` env (JSON array, see lib/cert-rescan.ts). Pilot certs
//   without an entry are skipped, not failed — by design. ACF-3 vendors opt in
//   to weekly re-scans as part of the cert fee; their entry is added here.

import { NextResponse } from "next/server";
import { loadRescanTargets, rescanCert, notifyRegression } from "../../../../lib/cert-rescan";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";
export const maxDuration = 600;  // up to 10 min — 7 probes × N certs × dual-judge

export async function POST(req: Request) {
  return handle(req);
}

// Allow GET for the curl-from-scheduler convenience case. Same auth.
export async function GET(req: Request) {
  return handle(req);
}

async function handle(req: Request): Promise<Response> {
  const secret = process.env.CRON_SECRET;
  if (!secret) {
    return NextResponse.json(
      { error: "cron_disabled", message: "CRON_SECRET not configured" },
      { status: 503 },
    );
  }
  const provided = req.headers.get("x-cron-secret");
  if (provided !== secret) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }

  const t0 = Date.now();
  const targets = loadRescanTargets();
  const outcomes = [];
  let rescanned = 0;
  let regressed = 0;
  let skipped = 0;
  let errored = 0;

  for (const target of targets) {
    const outcome = await rescanCert(target);
    outcomes.push(outcome);
    if (outcome.status === "ok") {
      rescanned++;
      if (outcome.regression_flag) {
        regressed++;
        await notifyRegression(outcome);
      }
    } else if (outcome.status === "skipped") {
      skipped++;
    } else {
      errored++;
    }
  }

  const duration_ms = Date.now() - t0;
  console.log(
    `[cron/cert-telemetry] targets=${targets.length} rescanned=${rescanned} regressed=${regressed} skipped=${skipped} errored=${errored} duration_ms=${duration_ms}`,
  );

  return NextResponse.json({
    ok: true,
    scanned_at: new Date().toISOString(),
    targets_configured: targets.length,
    rescanned,
    regressed,
    skipped,
    errored,
    duration_ms,
    outcomes: outcomes.map((o) => ({
      cert_id: o.cert_id,
      status: o.status,
      reason: o.reason,
      current_score: o.current_score,
      delta: o.delta,
      judge_agreement: o.judge_agreement_count != null && o.total_probes != null
        ? `${o.judge_agreement_count}/${o.total_probes}`
        : null,
      regression_flag: o.regression_flag ?? false,
    })),
  });
}
