# Deploying Demesne on Supabase

The **Supabase profile** — the deployment-side analogue of an emit target (the TypeScript
target is in [`ts/`](ts/README.md)). Demesne's generated RLS already reads
`current_setting('request.jwt.claims', true)::json ->> '<key>'` with policies `TO
authenticated` — which are **exactly Supabase's defaults** — so dropping into Supabase is
small: the only missing piece is getting the spec's claims-contract keys into that GUC.

On Supabase the JWT is minted by GoTrue and exposed to Postgres (via PostgREST) as the
`request.jwt.claims` GUC; app-controlled claims live in a user's `app_metadata`. The
profile emits a **custom access-token hook** that lifts each contract key from
`app_metadata` to a top-level claim, so the generated RLS reads them unchanged.

```
buildClaims(principal)  ──►  user.app_metadata
        ──►  custom access-token hook  (lifts each contract key to a top-level claim)
        ──►  request.jwt.claims        (PostgREST sets the GUC from the JWT)
        ──►  the generated RLS reads it and filters
```

A worked, runnable example lives in
[`ts/packages/example-app`](ts/packages/example-app) (`test/supabase.test.ts`).

## One-time caveat: keep the definer kernel out of `auth`

Demesne's SECURITY DEFINER kernel defaults to the `auth` schema — but on Supabase `auth`
is **reserved** for GoTrue. Put the kernel in a dedicated schema instead:

```
definers schema "demesne"   // in your .demesne spec — NOT "auth"
```

Governed tables stay in `public` (where Supabase app tables live; the request roles
already reach it).

## Deploy steps

### 1. Apply the authorization SQL

```sh
demesne emit app.demesne all > authz.sql
# apply authz.sql via a migration (definers in your `demesne` schema + ENABLE/FORCE RLS
# + the policies). Grant the request role what it needs:
#   grant usage on schema demesne to authenticated;
#   grant execute on all functions in schema demesne to authenticated;
```

### 2. Emit + register the access-token hook

```sh
demesne emit app.demesne --profile supabase > supabase-hook.sql
# apply supabase-hook.sql — it creates public.demesne_access_token_hook and grants it to
# supabase_auth_admin (and revokes it from authenticated/anon/public).
```

Register it as the **Custom Access Token** hook:

- Dashboard → Authentication → Hooks → "Custom Access Token" → select
  `public.demesne_access_token_hook`, **or**
- `supabase/config.toml`:
  ```toml
  [auth.hook.custom_access_token]
  enabled = true
  uri = "pg-functions://postgres/public/demesne_access_token_hook"
  ```

### 3. Populate `app_metadata` from the engine

When you provision or re-scope a user, set its `app_metadata` to the claims `buildClaims`
derives from your spec — no hand-mapped field names:

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
RLS enforces them. (A change to `app_metadata` takes effect on the next token refresh.)

## Role safety (the moat)

| Role | Use | RLS |
|---|---|---|
| `authenticated` | the request path (the connection role the policies target) | **enforced** (non-BYPASSRLS) |
| `anon` | unauthenticated requests | enforced |
| `service_role` | **trusted server-side / bootstrap only — never the request path** | **bypassed** (BYPASSRLS) |

A request-path query under `service_role` silently bypasses every policy — defeating the
moat. Keep `service_role` to server code that intends to bypass (seeding, admin jobs).

Verify the connection role is safe against your live database:

```sh
demesne check app.demesne "$SUPABASE_DB_URL"
# ok: ... the RLS connection role "authenticated" is not BYPASSRLS
```

## Verify end-to-end

The example round-trips the whole flow against a real project (or a local
Supabase-shaped Postgres if `$SUPABASE_DB_URL` is unset):

```sh
# Use the Session-pooler / IPv4 connection string from the dashboard (Connect → Session
# pooler); the direct db.<ref>.supabase.co:5432 endpoint is IPv6-only.
SUPABASE_DB_URL="postgresql://postgres.<ref>:<pw>@aws-0-<region>.pooler.supabase.com:5432/postgres" \
  pnpm --filter @demesne/example-app exec vitest run supabase
```

It asserts the hook lifts the contract keys, the RLS returns exactly the rows the subject
may see (owner + open, scoped by containment), and that `service_role` reads past the
policy.
