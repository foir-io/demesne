package demesne

import (
	"fmt"
	"strings"
	"testing"
)

const identifiersSpec = `
topology { level tenant level project parent tenant }

vocabulary staff {
  permission docs:read
  permission docs:manage
  preset viewer  @ project = docs:read
  preset steward @ project = *
  rank steward > viewer
}

rolestore staff {
  assignments role_grants
  kind        grantee_kind = "staff"
  subject     grantee_id
  scope       tenant_id project_id
  rolejoin    role_id roles id key
  revoked     revoked_at
}

subject staffer { anchor tenant reach descendants identifies sub roles configurable staff binds admin }

object doc {
  table docs
  scoped tenant > project
  relation curator: staffer via role
  permission view = curator @rls maps select
  permission edit = @kind("staff") @rls maps update
}
`

func emitFor(t *testing.T, src string) (defs []GenFn, rls string) {
	t.Helper()
	s, err := Parse(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	defs, err = s.EmitDefiners()
	if err != nil {
		t.Fatalf("emit definers: %v", err)
	}
	set, err := s.EmitRLS()
	if err != nil {
		t.Fatalf("emit rls: %v", err)
	}
	var b strings.Builder
	for _, p := range set.Policies {
		b.WriteString(p.Using)
		b.WriteString(" ")
		b.WriteString(p.Check)
		b.WriteString("\n")
	}
	return defs, b.String()
}

func TestIdentifiers_DefaultsToTextAndEmitsNoCast(t *testing.T) {
	defs, rls := emitFor(t, identifiersSpec)
	for _, d := range defs {
		if !strings.Contains(d.Sig, "text") {
			t.Errorf("without an identifiers declaration every id parameter stays text, got %q in %s", d.Sig, d.Name)
		}
	}
	if strings.Contains(rls, "::uuid") || strings.Contains(rls, "::bigint") {
		t.Errorf("default spec must emit no identifier cast:\n%s", rls)
	}
}

func TestIdentifiers_TypeIsAPureParameter(t *testing.T) {
	for _, idT := range []string{"uuid", "bigint", "citext"} {
		t.Run(idT, func(t *testing.T) {
			src := "identifiers " + idT + "\n" + identifiersSpec
			defs, rls := emitFor(t, src)

			var ranked *GenFn
			for i := range defs {
				if defs[i].Name == "staffer_has_doc_role" {
					ranked = &defs[i]
				}
			}
			if ranked == nil {
				t.Fatal("no role definer emitted")
			}
			want := fmt.Sprintf("user_id %s, check_tenant_id %s, check_project_id %s", idT, idT, idT)
			if ranked.Sig != want {
				t.Errorf("definer signature must carry the declared type\n got: %s\nwant: %s", ranked.Sig, want)
			}
			if !strings.Contains(rls, "'sub')::"+idT) {
				t.Errorf("identifier claims must be cast to the declared type:\n%s", rls)
			}
		})
	}
}

func TestIdentifiers_ValueClaimsAreNeverCast(t *testing.T) {
	_, rls := emitFor(t, "identifiers uuid\n"+identifiersSpec)
	if !strings.Contains(rls, "'kind')") {
		t.Fatalf("fixture no longer exercises @kind:\n%s", rls)
	}
	if strings.Contains(rls, "'kind')::uuid") {
		t.Errorf("@kind is a value claim compared to a string literal and must not be cast as an identifier:\n%s", rls)
	}
}

func TestIdentifiers_ScopeColumnsStayNativeForIndexUse(t *testing.T) {
	_, rls := emitFor(t, "identifiers uuid\n"+identifiersSpec)
	for _, col := range []string{"tenant_id::uuid", "project_id::uuid", " id::uuid"} {
		if strings.Contains(rls, col) {
			t.Errorf("column %q was cast; columns must stay native so indexes remain usable, only claims are cast:\n%s", col, rls)
		}
	}
	if !strings.Contains(rls, "tenant_id = (current_setting") {
		t.Errorf("expected a native column compared to a cast claim:\n%s", rls)
	}
}

func TestIdentifiers_RejectsDuplicateDeclaration(t *testing.T) {
	src := "identifiers uuid\nidentifiers bigint\n" + identifiersSpec
	if _, err := Parse(src); err == nil || !strings.Contains(err.Error(), "duplicate identifiers") {
		t.Errorf("expected a duplicate-declaration parse error, got %v", err)
	}
}
