-- AISeal F1+F2 — seed the 5 Private Pilot vendors into certifications.
-- These are the same records that were hardcoded in lib/registry.ts MOCK_CERTS.
-- vendor_domain left NULL during Pilot (vendors are fictional/demo); the
-- /api/verify endpoint returns "pilot_vendor" status when vendor_domain is NULL.

insert into public.certifications (
  cert_id, vendor_id, vendor_name, vendor_domain,
  product_name, product_version, industry, tier, status, trust_score,
  issued_date, expiry_date, frameworks, scope_description,
  logo_initial, logo_color
) values
(
  'ACF3-2026-0001', 'meridian-health', 'Meridian Health Systems', null,
  'ClinicalAssist', 'v4.2', 'healthcare', 'ACF-3', 'ACTIVE', 94,
  '2026-01-10', '2027-01-10',
  '{"owasp":true,"nist":true,"euAiAct":true,"mitreAtlas":true}'::jsonb,
  'RAG-based clinical decision support AI handling PHI. Full OWASP LLM Top 10 assessment covering LLM01–LLM07. NIST AI RMF GOVERN/MAP/MEASURE/MANAGE functions verified. EU AI Act Article 9 risk management documentation reviewed and approved.',
  'M', '#a855f7'
),
(
  'ACF2-2026-0002', 'vantage-legal', 'Vantage Legal AI', null,
  'DocReview Pro', 'v2.1', 'legal', 'ACF-2', 'ACTIVE', 88,
  '2026-02-14', '2027-02-14',
  '{"owasp":true,"nist":true,"euAiAct":false,"mitreAtlas":true}'::jsonb,
  'Contract analysis and due diligence AI. No PII/PHI handling beyond attorney-client privileged content. All mandatory OWASP controls pass (LLM01, LLM06, LLM07). Sensitive data controls (LLM02) verified. Output handling (LLM05) verified for generated legal summaries.',
  'V', '#0080ff'
),
(
  'ACF2-2026-0003', 'fincore-systems', 'FinCore Systems', null,
  'RiskAdvisor', 'v3.0', 'fintech', 'ACF-2', 'ACTIVE', 85,
  '2026-03-01', '2027-03-01',
  '{"owasp":true,"nist":true,"euAiAct":true,"mitreAtlas":false}'::jsonb,
  'AI-assisted credit risk scoring and loan decisioning. Handles financial PII. LLM02 (Sensitive Data Disclosure) mandatory for this architecture. NIST AI RMF bias and fairness documentation verified. EU AI Act high-risk AI system classification reviewed.',
  'F', '#0080ff'
),
(
  'ACF1-2026-0004', 'talentiq', 'TalentIQ', null,
  'HireAssist', 'v1.4', 'hr-tech', 'ACF-1', 'ACTIVE', 78,
  '2026-03-20', '2027-03-20',
  '{"owasp":true,"nist":false,"euAiAct":false,"mitreAtlas":false}'::jsonb,
  'Candidate screening and resume analysis AI. All three mandatory OWASP controls pass (LLM01, LLM06, LLM07). No RAG architecture — LLM04 not applicable. Does not generate executable output — LLM05 not applicable.',
  'T', '#00c853'
),
(
  'ACF1-2026-0005', 'nexus-support', 'Nexus AI', null,
  'SupportGPT', 'v2.8', 'other', 'ACF-1', 'UNDER_REVIEW', 76,
  '2026-04-01', '2027-04-01',
  '{"owasp":true,"nist":false,"euAiAct":false,"mitreAtlas":false}'::jsonb,
  'Customer support automation AI. All mandatory OWASP controls pass. Currently under scheduled 6-month review audit. Certificate remains valid during review period.',
  'N', '#f59e0b'
)
on conflict (cert_id) do nothing;  -- idempotent re-runs
