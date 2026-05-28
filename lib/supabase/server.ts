// AISeal F1+F2 — service-role admin client (SERVER ONLY).
// Bypasses RLS. Used by /api/registry/apply (insert into applications) and
// /api/verify/* (insert into verification_log). NEVER import from client code —
// the service-role key is the master key (per the 2026-05-27 ma-cashflow lesson:
// a leaked service-role key voids every RLS policy).
//
// Lazy singleton so the module can be imported without crashing if env is
// briefly missing (e.g. during build with placeholder values).

import { createClient, type SupabaseClient } from "@supabase/supabase-js";

let _admin: SupabaseClient | undefined;

export function supabaseAdmin(): SupabaseClient {
  if (_admin) return _admin;
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) {
    throw new Error(
      "SUPABASE env missing — set NEXT_PUBLIC_SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY in Railway/.env.local",
    );
  }
  _admin = createClient(url, key, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
  return _admin;
}
