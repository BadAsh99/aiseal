-- AISeal — cert_telemetry table.
--
-- Closes the v2.1 Validation gap for ACF-N posture claims. The marketing copy
-- on /disclosure-vs-evidence says "ACF-3 maintains a security posture" but
-- without re-scan telemetry that's a snapshot dressed up as a posture. This
-- table stores weekly re-scan results so /registry/{vendor_id} can render a
-- timeline of "posture maintained over N weeks" instead of a single number.
--
-- Pattern matches live_scans + verification_log: service-role only, no anon
-- policy. The UI reads it via the admin server client.
--
-- Audit trail per cert:
--   - score_at_cert  — the score the cert was issued with (baseline)
--   - current_score  — what this re-scan observed
--   - delta          — generated (current_score - score_at_cert)
--   - judge_*        — dual-judge agreement at this scan
--   - probe_results  — full per-probe breakdown for forensic dispute resolution
--   - vendor_endpoint — endpoint as scanned (may differ from cert's original)
--   - regression_flag — true if delta < -10 (alert was fired)

create table if not exists public.cert_telemetry (
  id                      uuid primary key default gen_random_uuid(),
  cert_id                 text not null references public.certifications(cert_id) on delete cascade,
  scanned_at              timestamptz not null default now(),
  score_at_cert           int,                                   -- baseline (cert.trust_score at issuance)
  current_score           int not null check (current_score between 0 and 100),
  delta                   int generated always as (current_score - score_at_cert) stored,
  judge_a_score           int,
  judge_b_score           int,
  judge_agreement_count   int,
  total_probes            int,
  probe_results           jsonb,                                 -- full per-probe breakdown
  vendor_endpoint         text,                                  -- endpoint at scan time (audit trail)
  scan_mode               text not null default 'cron_rescan',   -- cron_rescan | manual | dispute
  regression_flag         boolean not null default false,        -- delta < -10
  error_message           text,                                  -- if the re-scan itself failed
  created_at              timestamptz not null default now()
);

create index if not exists cert_telemetry_cert_id_idx     on public.cert_telemetry (cert_id, scanned_at desc);
create index if not exists cert_telemetry_regression_idx  on public.cert_telemetry (regression_flag) where regression_flag = true;
create index if not exists cert_telemetry_scanned_at_idx  on public.cert_telemetry (scanned_at desc);

alter table public.cert_telemetry enable row level security;
-- No public policies — service-role only. UI reads via supabaseAdmin().
grant all on public.cert_telemetry to service_role;

comment on table public.cert_telemetry is
  'Weekly re-scan results for active certifications. Closes the v2.1 Validation gap for ACF-N posture claims. Service-role only.';

-- Verify after running:
--   select relname, relrowsecurity from pg_class
--   where relname='cert_telemetry' and relnamespace='public'::regnamespace;  -- expect true
