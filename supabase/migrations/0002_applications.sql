-- AISeal F1+F2 — applications table (PRIVATE — service-role only)
-- Backs /api/registry/apply (replaces the ephemeral in-memory Map). Holds email,
-- business contact info, IP hash — must NEVER be exposed to anon.
--
-- Direct application of the 2026-05-27 RLS lesson: RLS-on with NO anon policy
-- means anon SELECT returns 0 rows (verify with anon-probe before promoting).

create table if not exists public.applications (
  id              uuid primary key default gen_random_uuid(),
  created_at      timestamptz not null default now(),
  -- Applicant identity
  email           text not null,
  company_name    text not null,
  vendor_domain   text,                       -- proposed cert vendor_domain
  -- Product info
  product_name    text not null,
  product_version text,
  tier_requested  text check (tier_requested in ('ACF-1','ACF-2','ACF-3')),
  industry        text check (industry in ('healthcare','legal','fintech','hr-tech','other')),
  -- Free-form context
  description     text,
  how_heard       text,
  notes           jsonb not null default '{}'::jsonb,
  -- Workflow
  status          text not null default 'pending'
                  check (status in ('pending','approved','rejected','withdrawn')),
  reviewed_at     timestamptz,
  reviewer_notes  text,
  cert_id         text references public.certifications(cert_id),   -- set when approved
  -- Abuse / audit
  ip_hash         text,
  user_agent      text
);

create index if not exists applications_created_at_idx on public.applications (created_at desc);
create index if not exists applications_email_idx      on public.applications (email);
create index if not exists applications_status_idx     on public.applications (status);

alter table public.applications enable row level security;
-- NO policies on purpose: anon and authenticated both get 0 rows.
grant all on public.applications to service_role;

-- Verify (and probe anon to 0 rows — today's hard-won discipline):
--   select relname, relrowsecurity from pg_class
--   where relname='applications' and relnamespace='public'::regnamespace;  -- expect true
