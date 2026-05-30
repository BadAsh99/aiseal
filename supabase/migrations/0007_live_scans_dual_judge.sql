-- AISeal dual-judge columns on live_scans.
-- Judge A = deterministic regex/heuristic (scan-probes.ts grade() functions).
-- Judge B = LLM-as-judge (GPT-4o if OPENAI_API_KEY set, else Claude Haiku).
-- Agreement rate between A and B is the published moat metric.

ALTER TABLE public.live_scans
  ADD COLUMN IF NOT EXISTS judge_b_verdicts      jsonb,
  ADD COLUMN IF NOT EXISTS judge_agreement_count int,
  ADD COLUMN IF NOT EXISTS judge_agreement_rate  real,
  ADD COLUMN IF NOT EXISTS judge_b_model         text,
  ADD COLUMN IF NOT EXISTS dual_judge_ran        boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS grader_version        text NOT NULL DEFAULT 'v2';
