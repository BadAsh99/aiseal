-- AISeal F4 — IRIS usage audit log.
-- Closes the F4 brand-existential gap from the 2026-05-27 audit by adding a
-- persistent global daily-cap counter for the two open Anthropic-backed routes
-- (/api/iris and /api/iris/chat). RLS-on, no anon policy, service-role only.
--
-- Used by lib/iris-guard.ts to enforce a global daily cap that the in-memory
-- per-IP rate limit can't enforce (in-memory resets on Railway cold start +
-- doesn't span replicas).

create table if not exists public.iris_usage (
  id              uuid primary key default gen_random_uuid(),
  created_at      timestamptz not null default now(),
  -- Route discriminator
  route           text not null check (route in ('iris','iris_chat')),
  -- Caller identity (for abuse pattern analysis)
  ip_hash         text,                          -- sha256(ip).slice(0,32)
  origin          text,                          -- request Origin header
  user_agent      text,
  -- Outcome
  ok              boolean not null,
  blocked_reason  text check (blocked_reason in (
    'rate_limit_ip','daily_cap','origin_blocked','validation','llm_error'
  )),
  -- Bookkeeping for spend estimation
  model           text,
  duration_ms     int,
  prompt_chars    int,
  reply_chars     int
);

create index if not exists iris_usage_created_at_idx on public.iris_usage (created_at desc);
create index if not exists iris_usage_route_idx     on public.iris_usage (route);
create index if not exists iris_usage_ip_hash_idx   on public.iris_usage (ip_hash);
create index if not exists iris_usage_blocked_idx   on public.iris_usage (blocked_reason)
  where blocked_reason is not null;

alter table public.iris_usage enable row level security;
-- No anon/authenticated policy. Service-role only.
grant all on public.iris_usage to service_role;

-- Verify:
--   select relname, relrowsecurity from pg_class
--   where relname='iris_usage' and relnamespace='public'::regnamespace;  -- expect true
