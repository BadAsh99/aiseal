-- AISeal F1+F2 — certifications table (public registry, anon-readable by design)
-- Backs lib/registry.ts CertRecord. RLS-on; anon SELECT allowed because this IS
-- the public registry. NO PII in this table — email/applicant data lives in
-- applications (private). Physical separation of concerns per the 2026-05-27 RLS
-- lesson ([[supabase-security-launch-gate]]).

create table if not exists public.certifications (
  cert_id            text primary key,                  -- e.g. ACF3-2026-0001
  vendor_id          text not null unique,              -- URL slug
  vendor_name        text not null,
  vendor_domain      text,                              -- the domain bound to this cert; used by /api/verify to validate Origin/Referer (NULL during Pilot)
  product_name       text not null,
  product_version    text not null,
  industry           text not null check (industry in ('healthcare','legal','fintech','hr-tech','other')),
  tier               text not null check (tier in ('ACF-1','ACF-2','ACF-3')),
  status             text not null check (status in ('ACTIVE','UNDER_REVIEW','SUSPENDED','EXPIRED')),
  trust_score        int  not null check (trust_score between 0 and 100),
  issued_date        date not null,
  expiry_date        date not null,
  frameworks         jsonb not null default '{}'::jsonb,  -- { owasp, nist, euAiAct, mitreAtlas } booleans
  scope_description  text not null,
  logo_initial       text not null,
  logo_color         text not null,
  created_at         timestamptz not null default now(),
  updated_at         timestamptz not null default now()
);

create index if not exists certifications_vendor_id_idx on public.certifications (vendor_id);
create index if not exists certifications_tier_idx     on public.certifications (tier);
create index if not exists certifications_status_idx   on public.certifications (status);
create index if not exists certifications_industry_idx on public.certifications (industry);

alter table public.certifications enable row level security;

-- Public registry: anon SELECT is the WHOLE POINT.
create policy "anon_read_all" on public.certifications
  for select to anon using (true);

-- service_role bypasses RLS; explicit grant for clarity.
grant select on public.certifications to anon;
grant all    on public.certifications to service_role;

-- Verify after running:
--   select relname, relrowsecurity from pg_class
--   where relname='certifications' and relnamespace='public'::regnamespace;  -- expect true
