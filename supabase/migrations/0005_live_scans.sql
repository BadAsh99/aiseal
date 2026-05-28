-- AISeal F3 — live endpoint scan audit log.
-- Every /api/scan/live request gets a row here. Private — service-role only.
-- Vendor api keys are NEVER stored (the route never logs them). We store the
-- endpoint URL host, the model name, the per-probe verdicts, and the final
-- score, so we can reproduce / dispute / suspend a cert later.

create table if not exists public.live_scans (
  id                uuid primary key default gen_random_uuid(),
  created_at        timestamptz not null default now(),
  -- Caller identity (for rate-limit + abuse audit)
  email             text,
  ip_hash           text,
  user_agent        text,
  -- Target
  endpoint_host     text not null,                 -- hostname only, no path
  endpoint_type     text not null check (endpoint_type in ('openai','anthropic')),
  model             text not null,
  vendor_domain     text,                          -- registered domain at scan time, if any
  vendor_id         text references public.certifications(vendor_id),  -- linked if matched
  -- Result
  trust_score       int not null check (trust_score between 0 and 100),
  probes_total      int not null,
  probes_passed     int not null default 0,
  probes_failed     int not null default 0,
  probes_partial    int not null default 0,
  probes_errored    int not null default 0,
  findings          jsonb not null default '[]'::jsonb,   -- [{ id, owasp, verdict, evidence, excerpt }]
  -- Health
  duration_ms       int not null,
  ssrf_check        text not null,                 -- the ssrf reason code (should be "ok")
  errored           boolean not null default false,
  error_message     text
);

create index if not exists live_scans_created_at_idx  on public.live_scans (created_at desc);
create index if not exists live_scans_endpoint_idx    on public.live_scans (endpoint_host);
create index if not exists live_scans_vendor_id_idx   on public.live_scans (vendor_id);
create index if not exists live_scans_score_idx       on public.live_scans (trust_score);

alter table public.live_scans enable row level security;
-- No anon policy; private audit log. Service-role only.
grant all on public.live_scans to service_role;

-- Verify:
--   select relname, relrowsecurity from pg_class
--   where relname='live_scans' and relnamespace='public'::regnamespace;  -- expect true
