-- Supabase-shaped roles. Idempotent: on a real Supabase project these already exist (so
-- every branch is skipped); on a local cluster it creates the same role set so the round-
-- trip exercises identical SQL in both places. anon/authenticated are the request roles
-- (non-BYPASSRLS — the moat); service_role is the trusted server role (BYPASSRLS, off the
-- request path); supabase_auth_admin owns/executes the auth hook.
do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'anon') then
    create role anon nologin noinherit;
  end if;
  if not exists (select 1 from pg_roles where rolname = 'authenticated') then
    create role authenticated nologin noinherit;
  end if;
  if not exists (select 1 from pg_roles where rolname = 'service_role') then
    create role service_role nologin noinherit bypassrls;
  end if;
  if not exists (select 1 from pg_roles where rolname = 'supabase_auth_admin') then
    create role supabase_auth_admin nologin noinherit;
  end if;
end
$$;
