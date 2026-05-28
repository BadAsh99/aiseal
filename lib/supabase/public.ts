// AISeal F1+F2 — anon client for PUBLIC reads (registry + per-cert lookups).
// Subject to RLS. anon SELECT on `certifications` is granted in 0001_certifications.sql
// (the registry IS public by design). Anon CANNOT read `applications` or
// `verification_log` (no policy granted) — those queries return 0 rows.
//
// Used in server components (registry/page.tsx, vendor_id/page.tsx) and in the
// SVG badge route (publicly reachable).

import { createClient, type SupabaseClient } from "@supabase/supabase-js";

let _anon: SupabaseClient | undefined;

export function supabasePublic(): SupabaseClient {
  if (_anon) return _anon;
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const key = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
  if (!url || !key) {
    throw new Error(
      "SUPABASE env missing — set NEXT_PUBLIC_SUPABASE_URL + NEXT_PUBLIC_SUPABASE_ANON_KEY",
    );
  }
  _anon = createClient(url, key, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
  return _anon;
}
