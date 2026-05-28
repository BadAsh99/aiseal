-- AISeal F1+F2 — verification_log (PRIVATE audit trail of /api/verify/{cert_id} calls)
-- Logs every public-facing verify call so we can detect badge-forgery attempts
-- (origin_mismatch) and surface "live verification activity" without exposing raw
-- request data publicly. RLS-on + no anon policy — service-role only.

create table if not exists public.verification_log (
  id            uuid primary key default gen_random_uuid(),
  called_at     timestamptz not null default now(),
  cert_id       text,                             -- stored as text (NOT FK) so we can log "cert_not_found" calls too
  origin        text,                             -- Origin header from caller
  referer       text,                             -- Referer header (note: HTTP spec misspells)
  result        text not null
                check (result in ('verified','origin_mismatch','no_origin','cert_not_found','cert_inactive')),
  ip_hash       text,
  user_agent    text
);

create index if not exists verification_log_cert_id_idx   on public.verification_log (cert_id);
create index if not exists verification_log_called_at_idx on public.verification_log (called_at desc);
create index if not exists verification_log_result_idx    on public.verification_log (result);

alter table public.verification_log enable row level security;
-- No anon policy. Reads + writes only via service-role from server routes.
grant all on public.verification_log to service_role;
