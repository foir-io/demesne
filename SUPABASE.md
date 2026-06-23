# Deploying Demesne on Supabase

This guide is for running Demesne-generated Row-Level Security on Supabase. If you already
have a `.demesne` spec, it takes you from the emitted SQL to a project where the database
enforces your rules on every request.

Supabase is a close fit out of the box. The RLS that Demesne emits reads its claims from
`current_setting('request.jwt.claims', true)::json ->> '<key>'` with policies `TO
authenticated`, and those are Supabase's defaults. The one thing you have to set up is
getting your spec's claims into that setting.

## How the claims get to the database

On Supabase, GoTrue mints the JWT and PostgREST exposes it to Postgres as the
`request.jwt.claims` setting. The claims your app controls live in a user's
`app_metadata`. Demesne's Supabase profile emits a custom access-token hook that copies
each claim from `app_metadata` up to a top-level claim, so the generated RLS reads them
without any change.

```
buildClaims(principal)  ──►  user.app_metadata
        ──►  custom access-token hook  (lifts each contract key to a top-level claim)
        ──►  request.jwt.claims        (PostgREST sets the GUC from the JWT)
        ──►  the generated RLS reads it and filters
```

A complete, runnable example lives in [`ts/packages/example-app`](ts/packages/example-app),
in `test/supabase.test.ts`. The TypeScript emit target itself lives in [`ts/`](ts/README.md).

## Before you start: keep the kernel out of `auth`

Demesne generates a set of trusted `SECURITY DEFINER` functions that the policies call.
By default they go in the `auth` schema, but Supabase reserves `auth` for GoTrue. Put them
in a dedicated schema instead:

```
definers schema "demesne"   // in your .demesne spec — NOT "auth"
```

Your governed tables stay in `public`, alongside the rest of your Supabase app tables,
where the request roles already have access.

## Deploy steps

### 1. Apply the authorization SQL

```sh
demesne emit app.demesne all > authz.sql
# apply authz.sql via a migration (definers in your `demesne` schema + ENABLE/FORCE RLS
# + the policies). Grant the request role what it needs:
#   grant usage on schema demesne to authenticated;
#   grant execute on all functions in schema demesne to authenticated;
```

### 2. Emit and register the access-token hook

```sh
demesne emit app.demesne --profile supabase > supabase-hook.sql
# apply supabase-hook.sql — it creates public.demesne_access_token_hook and grants it to
# supabase_auth_admin (and revokes it from authenticated/anon/public).
```

Register it as the Custom Access Token hook one of two ways:

- Dashboard → Authentication → Hooks → "Custom Access Token" → select
  `public.demesne_access_token_hook`, or
- `supabase/config.toml`:
  ```toml
  [auth.hook.custom_access_token]
  enabled = true
  uri = "pg-functions://postgres/public/demesne_access_token_hook"
  ```

### 3. Populate `app_metadata` from the engine

When you provision or re-scope a user, set its `app_metadata` to the claims that
`buildClaims` derives from your spec. You don't map any field names by hand:

```ts
import { buildClaims } from "@demesne/runtime";
import { claims } from "./app.demesne.projection.js"; // demesne emit app.demesne --target ts

const app_metadata = buildClaims(claims, {
  subject: "member",
  id: userId,
  scopes: { org: orgId, workspace: workspaceId },
});

await supabaseAdmin.auth.admin.updateUserById(userId, { app_metadata });
```

On the user's next token mint, the hook lifts those keys into `request.jwt.claims` and the
RLS enforces them. A change to `app_metadata` takes effect on the next token refresh.

## Role safety

Pick the right connection role. Two of Supabase's built-in roles run under RLS; one
bypasses it.

| Role | Use | RLS |
|---|---|---|
| `authenticated` | the request path (the connection role the policies target) | enforced (non-BYPASSRLS) |
| `anon` | unauthenticated requests | enforced |
| `service_role` | **trusted server-side / bootstrap only — never the request path** | bypassed (BYPASSRLS) |

A request-path query under `service_role` silently bypasses every policy. That defeats the
enforcement floor — the moat your spec is supposed to provide. Keep `service_role` for
server code that means to bypass RLS, such as seeding and admin jobs.

Check that your connection role is safe against the live database:

```sh
demesne check app.demesne "$SUPABASE_DB_URL"
# ok: ... the RLS connection role "authenticated" is not BYPASSRLS
```

## Verify end-to-end

The example runs the whole flow against a real project. If `$SUPABASE_DB_URL` is unset, it
runs against a local Supabase-shaped Postgres instead:

```sh
# Use the Session-pooler / IPv4 connection string from the dashboard (Connect → Session
# pooler); the direct db.<ref>.supabase.co:5432 endpoint is IPv6-only.
SUPABASE_DB_URL="postgresql://postgres.<ref>:<pw>@aws-0-<region>.pooler.supabase.com:5432/postgres" \
  pnpm --filter @demesne/example-app exec vitest run supabase
```

It checks three things: the hook lifts the contract keys, the RLS returns exactly the rows
the subject may see (owner plus open records, scoped by containment), and `service_role`
reads past the policy.
