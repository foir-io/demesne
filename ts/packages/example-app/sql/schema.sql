-- The adopter's underlying schema for examples/roundtrip.demesne. Demesne governs these
-- EXISTING tables; it does not create them. Applied as superuser BEFORE generated/
-- policies.sql (which adds the auth.* definers + RLS). The column names deliberately
-- follow none of the usual conventions (note_pk, org_ref, ws_ref, …), proving the
-- generated SQL binds to whatever the schema declares.

CREATE SCHEMA IF NOT EXISTS auth;

-- The governed object.
CREATE TABLE notes (
  note_pk    text PRIMARY KEY,
  org_ref    text NOT NULL,
  ws_ref     text NOT NULL,
  owner_ref  text,
  visibility text NOT NULL DEFAULT 'private'
);

-- The per-record grant (ACL) store. Carries the containment scope columns (org_ref,
-- ws_ref) the grant write threads, plus the grant tuple. Not RLS-governed in this spec.
CREATE TABLE note_acl (
  org_ref      text NOT NULL,
  ws_ref       text NOT NULL,
  note_ref     text NOT NULL,
  grantee_kind text NOT NULL,
  grantee_ref  text NOT NULL,
  perm         text NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (note_ref, grantee_kind, grantee_ref, perm)
);

-- The RLS connection role: non-LOGIN, non-BYPASSRLS (the moat). The app assumes it per
-- transaction via SET LOCAL ROLE (sessionSetupSQL).
CREATE ROLE authenticated NOLOGIN;
GRANT USAGE ON SCHEMA public TO authenticated;
GRANT USAGE ON SCHEMA auth TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON notes TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON note_acl TO authenticated;
