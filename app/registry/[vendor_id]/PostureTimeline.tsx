// AISeal — "Posture Over Time" timeline for a single cert.
//
// Server component. Reads cert_telemetry via the service-role admin client
// (cert_telemetry is private; no anon policy). Renders an inline-SVG sparkline
// of `current_score` over `scanned_at` plus the last-scan summary and a
// regression banner if any rescan in the last 4 weeks tripped the flag.
//
// Closes the v2.1 Validation gap on Claim D ("ACF-3 maintains a posture"):
// shows the auditor concrete evidence that the snapshot is being maintained,
// not a single number that was true once.

import { supabaseAdmin } from "../../../lib/supabase/server";

interface TelemetryRow {
  id: string;
  cert_id: string;
  scanned_at: string;
  score_at_cert: number | null;
  current_score: number;
  delta: number | null;
  judge_agreement_count: number | null;
  total_probes: number | null;
  regression_flag: boolean;
  error_message: string | null;
}

interface Props {
  certId: string;
  baselineScore: number;
}

function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString("en-US", {
    month: "short", day: "numeric", year: "numeric",
  });
}

function Sparkline({ points, baseline }: { points: TelemetryRow[]; baseline: number }) {
  // points come oldest→newest after we reverse the desc query
  if (points.length === 0) {
    return null;
  }
  const W = 480;
  const H = 110;
  const PAD_X = 24;
  const PAD_Y = 16;
  const innerW = W - PAD_X * 2;
  const innerH = H - PAD_Y * 2;

  // Y scale: clamp 0..100 but auto-zoom around the data with baseline visible
  const minY = Math.max(0, Math.min(baseline - 5, ...points.map((p) => p.current_score)) - 2);
  const maxY = Math.min(100, Math.max(baseline + 5, ...points.map((p) => p.current_score)) + 2);
  const yRange = Math.max(1, maxY - minY);

  const xAt = (i: number) =>
    PAD_X + (points.length <= 1 ? innerW / 2 : (innerW * i) / (points.length - 1));
  const yAt = (v: number) => PAD_Y + innerH * (1 - (v - minY) / yRange);

  const baselineY = yAt(baseline);
  const path = points.map((p, i) => `${i === 0 ? "M" : "L"} ${xAt(i).toFixed(1)} ${yAt(p.current_score).toFixed(1)}`).join(" ");

  return (
    <svg
      viewBox={`0 0 ${W} ${H}`}
      role="img"
      aria-label="Re-scan score over time"
      style={{ width: "100%", height: "auto", display: "block" }}
    >
      {/* Baseline (score_at_cert) */}
      <line
        x1={PAD_X} x2={W - PAD_X} y1={baselineY} y2={baselineY}
        stroke="#6b7280" strokeWidth="1" strokeDasharray="3 4" opacity="0.6"
      />
      <text x={W - PAD_X} y={baselineY - 4} textAnchor="end" fontSize="9" fill="#9ca3af">
        baseline {baseline}
      </text>

      {/* Score line */}
      <path d={path} fill="none" stroke="#0080ff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />

      {/* Points */}
      {points.map((p, i) => (
        <g key={p.id}>
          <circle
            cx={xAt(i)}
            cy={yAt(p.current_score)}
            r={p.regression_flag ? 4.5 : 3}
            fill={p.regression_flag ? "#f85149" : "#0080ff"}
            stroke="#0b1219"
            strokeWidth="1"
          />
          <title>{`${formatDate(p.scanned_at)} — ${p.current_score} (Δ${(p.delta ?? 0) >= 0 ? "+" : ""}${p.delta ?? 0})`}</title>
        </g>
      ))}

      {/* X axis labels: first + last only */}
      {points.length > 0 && (
        <>
          <text x={PAD_X} y={H - 2} fontSize="9" fill="#9ca3af">
            {formatDate(points[0].scanned_at)}
          </text>
          <text x={W - PAD_X} y={H - 2} textAnchor="end" fontSize="9" fill="#9ca3af">
            {formatDate(points[points.length - 1].scanned_at)}
          </text>
        </>
      )}
    </svg>
  );
}

export default async function PostureTimeline({ certId, baselineScore }: Props) {
  let rows: TelemetryRow[] = [];
  let errorMessage: string | null = null;
  try {
    const admin = supabaseAdmin();
    const { data, error } = await admin
      .from("cert_telemetry")
      .select("id, cert_id, scanned_at, score_at_cert, current_score, delta, judge_agreement_count, total_probes, regression_flag, error_message")
      .eq("cert_id", certId)
      .order("scanned_at", { ascending: false })
      .limit(52);  // ~1 year of weekly rescans
    if (error) {
      errorMessage = error.message;
    } else {
      rows = (data ?? []) as TelemetryRow[];
    }
  } catch (e) {
    errorMessage = e instanceof Error ? e.message : "unknown";
  }

  // Reverse to oldest→newest for the sparkline.
  const chronological = [...rows].reverse();
  const latest = rows[0];
  const fourWeeksAgo = Date.now() - 28 * 24 * 60 * 60 * 1000;
  const recentRegression = rows.find(
    (r) => r.regression_flag && new Date(r.scanned_at).getTime() >= fourWeeksAgo,
  );

  return (
    <div
      className="rounded-xl overflow-hidden"
      style={{ border: "1px solid var(--border-mid)" }}
    >
      <div
        className="px-5 py-3 flex items-center justify-between gap-3"
        style={{ background: "var(--bg-surface)", borderBottom: "1px solid var(--border-mid)" }}
      >
        <p className="text-xs font-semibold uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>
          Posture Over Time
        </p>
        <p className="text-xs" style={{ color: "var(--text-subtle)" }}>
          {rows.length === 0
            ? "No re-scan history yet"
            : `${rows.length} re-scan${rows.length === 1 ? "" : "s"} on record`}
        </p>
      </div>

      <div className="px-5 py-4 flex flex-col gap-4" style={{ background: "var(--bg-elevated)" }}>
        {errorMessage && (
          <p className="text-xs" style={{ color: "#f85149" }}>
            Could not load telemetry: {errorMessage}
          </p>
        )}

        {!errorMessage && rows.length === 0 && (
          <p className="text-sm leading-relaxed" style={{ color: "var(--text-muted)" }}>
            Weekly re-scans publish here once this cert is enrolled in AISeal&apos;s posture monitoring.
            Until the first re-scan lands, the registry shows the issuance snapshot only.
          </p>
        )}

        {recentRegression && (
          <div
            className="rounded-md px-3 py-2.5"
            style={{
              background: "rgba(248,81,73,0.08)",
              border: "1px solid rgba(248,81,73,0.25)",
            }}
          >
            <p className="text-xs font-semibold" style={{ color: "#f85149" }}>
              Posture regression flagged {formatDate(recentRegression.scanned_at)}
            </p>
            <p className="text-xs mt-1" style={{ color: "var(--text-muted)" }}>
              Score dropped to {recentRegression.current_score} (Δ{(recentRegression.delta ?? 0) >= 0 ? "+" : ""}{recentRegression.delta ?? 0} from the certificate baseline of {recentRegression.score_at_cert ?? baselineScore}). Threshold for a regression flag is -10.
            </p>
          </div>
        )}

        {chronological.length > 0 && (
          <Sparkline points={chronological} baseline={baselineScore} />
        )}

        {latest && (
          <div
            className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-2"
            style={{ borderTop: "1px solid var(--border-subtle)" }}
          >
            <Stat label="Latest score" value={String(latest.current_score)} />
            <Stat
              label="Δ from baseline"
              value={`${(latest.delta ?? 0) >= 0 ? "+" : ""}${latest.delta ?? 0}`}
              accent={latest.regression_flag ? "#f85149" : (latest.delta ?? 0) >= 0 ? "#00c853" : "#f59e0b"}
            />
            <Stat
              label="Judge agreement"
              value={
                latest.judge_agreement_count != null && latest.total_probes != null
                  ? `${latest.judge_agreement_count}/${latest.total_probes}`
                  : "—"
              }
            />
            <Stat label="Last re-scan" value={formatDate(latest.scanned_at)} />
          </div>
        )}
      </div>
    </div>
  );
}

function Stat({ label, value, accent }: { label: string; value: string; accent?: string }) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-xs uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>
        {label}
      </span>
      <span className="text-sm font-semibold" style={{ color: accent ?? "var(--text-primary)" }}>
        {value}
      </span>
    </div>
  );
}
