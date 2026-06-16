package demesne

import (
	"strings"
	"testing"
)

// An ADMIN-PLANE descriptor: the resource is owned by the admin who authored it
// (`owner admin via created_by`, no customer column at all) and its public read
// is actor-scoped to operators (`read "public" for admin` → visible project-wide
// to callers with no customer claim, never to a customer / the public API). This
// is the notes shape: operator-authored, project-wide-visible-to-operators, with
// per-resource private + @mention grants on the shared acl store.
const adminPlaneNoteSpec = `
topology {
  level platform virtual
  level tenant   parent platform
  level project  parent tenant
}
vocabulary admin { permission c:r preset pa @ project = c:r }
vocabulary cust  { permission self:read }
rolestore admin {
  assignments ra
  kind        principal_kind = "admin"
  subject     principal_id
  scope       tenant_id project_id
  rolejoin    role_id roles id key
  revoked     revoked_at
}
subject admin    { anchor tenant  reach descendants identifies sub roles configurable admin binds admin }
subject customer { anchor project reach self identifies customer_id roles configurable cust binds owner }
subject service  { anchor project reach self identifies sub roles none }
object note {
  table  notes
  scoped tenant > project
  descriptor {
    owner  admin via created_by
    mode   via access_mode
    modes  private + read "public" for admin + list "admin"
    grants via edge resource_acl(resource_id, principal_kind, principal_id, access) where resource_type = "note"
  }
  permission view = @descriptor @rls maps select
}
`

func TestDescriptorAdminPlaneActorScoped(t *testing.T) {
	s, err := Parse(adminPlaneNoteSpec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	res, err := s.EmitRLS()
	if err != nil {
		t.Fatalf("emit rls: %v", err)
	}
	sql := res.PolicySQL("authenticated")

	// Capability 1 — admin-plane owner: the owner term reads created_by against
	// the admin subject's claim (sub), NOT a customer column.
	if !strings.Contains(sql, "created_by = (current_setting('request.jwt.claims', true)::json ->> 'sub')") {
		t.Errorf("missing admin-plane owner term (created_by = sub):\n%s", sql)
	}
	// Capability 2 — actor-scoped public: the "public" sentinel is gated to the
	// operator plane (no customer claim), so it never opens to a customer.
	if !strings.Contains(sql, "access_mode = 'public' AND (current_setting('request.jwt.claims', true)::json ->> 'customer_id') IS NULL") {
		t.Errorf("public read mode not scoped to the operator plane:\n%s", sql)
	}

	// The admin grant disjunct is read against the admin subject's own claim (sub),
	// since the descriptor owner principal is admin (not customer).
	if !strings.Contains(sql, "(current_setting('request.jwt.claims', true)::json ->> 'sub'), notes.id, 'read')") {
		t.Errorf("admin grant disjunct not bound to the admin claim:\n%s", sql)
	}

	// The Expand accessor enumerator tags owner rows with the admin kind and reads
	// the created_by column — no customer column referenced for an admin-plane note.
	accessors := findAccessor(t, adminPlaneNoteSpec, "notes")
	if !strings.Contains(accessors, "created_by") || strings.Contains(accessors, "customer_id") {
		t.Errorf("accessor enumerator should read created_by, never customer_id:\n%s", accessors)
	}
	if !strings.Contains(accessors, "'admin'") {
		t.Errorf("accessor owner rows should be tagged with the admin kind:\n%s", accessors)
	}
}

// An UNSCOPED public read (a public record served to the world) stays a bare
// sentinel check with no plane predicate — the capability is opt-in, so records
// remain byte-identical.
func TestDescriptorUnscopedReadUnchanged(t *testing.T) {
	s, err := Parse(reachGrantSpec) // record descriptor: read "public_project", no `for`
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	res, err := s.EmitRLS()
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	sql := res.PolicySQL("authenticated")
	// The world-readable sentinel is bare — no plane AND clause grafted on.
	if strings.Contains(sql, "access_mode = 'public_project' AND") {
		t.Errorf("unscoped read mode leaked a plane predicate:\n%s", sql)
	}
	if !strings.Contains(sql, "access_mode = 'public_project'") {
		t.Errorf("expected the bare public_project sentinel:\n%s", sql)
	}
}
