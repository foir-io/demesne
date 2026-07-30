package demesne

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCanonical_RBAC(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("examples", "canonical", "rbac.demesne"))
	if err != nil {
		t.Fatalf("read spec: %v", err)
	}
	s, err := Parse(string(src))
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
	sub := "(current_setting('request.jwt.claims', true)::json ->> 'sub')"

	sel := findPolicy(res, "resources_select")
	if sel == nil {
		t.Fatalf("no resources_select policy (unsupported: %v)", res.Unsupported)
	}
	if !strings.Contains(sel.Using, "auth.staff_has_resource_role("+sub+", tenant_id, project_id)") {
		t.Errorf("read verb not gated by the any-role definer:\n%s", sel.Using)
	}

	upd := findPolicy(res, "resources_update")
	if upd == nil {
		t.Fatal("no resources_update policy")
	}
	if !strings.Contains(upd.Using, "auth.staff_has_perm("+sub+", tenant_id, project_id, 'resource:write')") {
		t.Errorf("write verb not gated by the capability definer:\n%s", upd.Using)
	}
	if strings.Contains(upd.Using, "staff_has_resource_role") {
		t.Errorf("write verb must not fall back to the any-role gate:\n%s", upd.Using)
	}

	for verb, pol := range map[string]*Policy{"select": sel, "update": upd} {
		if !strings.Contains(pol.Using, "tenant_id = (current_setting") ||
			!strings.Contains(pol.Using, "project_id = (current_setting") {
			t.Errorf("%s verb dropped tenancy containment:\n%s", verb, pol.Using)
		}
	}

	defs, err := s.EmitDefiners()
	if err != nil {
		t.Fatalf("emit definers: %v", err)
	}
	body := map[string]string{}
	for _, d := range defs {
		body[d.Name] = d.CreateSQL()
	}
	anyRole := body["staff_has_resource_role"]
	if anyRole == "" {
		t.Fatalf("missing staff_has_resource_role definer; got %v", defKeys(body))
	}
	for _, frag := range []string{
		"SECURITY DEFINER",
		"FROM role_grants ra JOIN roles r ON r.id = ra.role_id",
		"ra.grantee_kind = 'staff'",
		"ra.grantee_id = user_id",
		"ra.revoked_at IS NULL",
		"r.key IN ('editor', 'viewer')",
	} {
		if !strings.Contains(anyRole, frag) {
			t.Errorf("staff_has_resource_role missing %q in:\n%s", frag, anyRole)
		}
	}

	perm := body["staff_has_perm"]
	if !strings.Contains(perm, "p_perm = ANY(r.permissions)") {
		t.Errorf("staff_has_perm should test the permissions array:\n%s", perm)
	}
	if strings.Contains(perm, "r.key IN") {
		t.Errorf("capability gating must not fall back to matching role keys:\n%s", perm)
	}
}

func defKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
