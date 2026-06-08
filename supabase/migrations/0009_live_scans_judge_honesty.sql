-- AISeal scanner v0.3.2 — honest dual-judge columns on live_scans.
-- A Judge-B failure must no longer fake a dual-confirmation: we record how many
-- probes lost their second opinion, the overall confidence label, and whether the
-- only judge was same-lineage (claude-haiku judging a Claude target, no OpenAI).

ALTER TABLE public.live_scans
  ADD COLUMN IF NOT EXISTS judge_b_unavailable_count int,
  ADD COLUMN IF NOT EXISTS judge_confidence          text,   -- dual-confirmed | partial | single-judge
  ADD COLUMN IF NOT EXISTS judge_same_lineage        boolean;
