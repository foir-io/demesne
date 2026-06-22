-- The adopter's schema + governed tables for examples/supabase.demesne, in the idiomatic
-- Supabase layout: tables in `public` (where app tables go), the SECURITY DEFINER kernel
-- in a DEDICATED `demesne` schema (NOT Supabase's reserved `auth`). Applied (as the
-- connection role) before generated/supabase/{policies,hook}.sql. Idempotent: drops +
-- recreates the demo tables for a clean round-trip each run.

create schema if not exists demesne; -- the SECURITY DEFINER kernel (not Supabase's `auth`)

drop table if exists public.note_acl;
drop table if exists public.notes;

create table public.notes (
  note_pk    text primary key,
  org_ref    text not null,
  ws_ref     text not null,
  owner_ref  text,
  visibility text not null default 'private'
);

create table public.note_acl (
  org_ref      text not null,
  ws_ref       text not null,
  note_ref     text not null,
  grantee_kind text not null,
  grantee_ref  text not null,
  perm         text not null,
  created_at   timestamptz not null default now(),
  primary key (note_ref, grantee_kind, grantee_ref, perm)
);

-- The request role reaches the tables + the definer schema (the definers' EXECUTE is
-- granted after they exist; see the round-trip harness). On a real project Supabase's
-- default privileges already grant `authenticated` on public tables; these are explicit
-- so the local Supabase-shaped cluster behaves identically.
grant usage on schema demesne to authenticated;
grant select, insert, update, delete on public.notes to authenticated;
grant select, insert, update, delete on public.note_acl to authenticated;

-- service_role is the trusted server role (BYPASSRLS). On a real project it is already
-- granted broadly; granted here so the local Supabase-shaped cluster matches (BYPASSRLS
-- skips the policy but still needs the table privilege).
grant usage on schema demesne to service_role;
grant select, insert, update, delete on public.notes to service_role;
grant select, insert, update, delete on public.note_acl to service_role;
