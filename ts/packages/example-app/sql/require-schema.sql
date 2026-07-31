-- The adopter's schema for examples/require.demesne. Applied as superuser BEFORE
-- generated/require/policies.sql.
--
-- auth.invitation_projects_in_tenant is the ONE thing here Demesne does not generate:
-- it is the `external predicate` the spec declares and the `require create` clause
-- calls. The spec names it, the compiler emits the call and refuses to compile if the
-- declaration is missing, but the body is the adopter's — which is why it lives in this
-- file and not in the generated one.

CREATE SCHEMA IF NOT EXISTS auth;

CREATE TABLE projects (
  id        text PRIMARY KEY,
  tenant_id text NOT NULL
);

CREATE TABLE invitations (
  id          text PRIMARY KEY,
  tenant_id   text NOT NULL,
  invited_by  text,
  email       text NOT NULL,
  project_ids text[] NOT NULL DEFAULT '{}'::text[]
);

CREATE TABLE roles (
  id          text PRIMARY KEY,
  key         text NOT NULL,
  permissions text[] NOT NULL DEFAULT '{}'::text[]
);

CREATE TABLE role_assignments (
  id             text PRIMARY KEY,
  principal_kind text NOT NULL,
  principal_id   text NOT NULL,
  tenant_id      text,
  project_id     text,
  role_id        text NOT NULL,
  revoked_at     timestamptz
);

CREATE FUNCTION auth.invitation_projects_in_tenant(
  check_tenant_id text, check_project_ids text[])
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT NOT EXISTS (
    SELECT 1
    FROM unnest(coalesce(check_project_ids, '{}'::text[])) AS want(project_id)
    WHERE NOT EXISTS (SELECT 1 FROM projects p
                       WHERE p.id = want.project_id
                         AND p.tenant_id = check_tenant_id)
  );
$$;

CREATE ROLE authenticated NOLOGIN;
GRANT USAGE ON SCHEMA public TO authenticated;
GRANT USAGE ON SCHEMA auth TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON invitations TO authenticated;
GRANT SELECT ON projects TO authenticated;
GRANT SELECT ON roles TO authenticated;
GRANT SELECT ON role_assignments TO authenticated;
REVOKE ALL ON FUNCTION auth.invitation_projects_in_tenant(text, text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION auth.invitation_projects_in_tenant(text, text[]) TO authenticated;
