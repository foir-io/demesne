package demesne

import (
	"strings"
	"testing"
)

// A @check permission compiles its predicate (the same owner/mode/grant vocabulary
// @rls accepts) into a callable Can<Verb> point-check with no RLS policy. `serve`
// is an arbitrary verb name: here a reach narrower than the SELECT policy.
const checkLayerSpec = `
topology { level tenant level project parent tenant }
vocabulary cust { permission self:read }
subject customer { anchor project reach self identifies customer_id roles configurable cust binds owner }
object doc {
  table  docs
  scoped tenant > project
  relation owner:   customer via owner_id where owner_kind = "customer"
  relation grantee: customer via grant dacl(resource_id, principal_kind, principal_id, access) where resource_type = "doc"
  permission view  = @app_scope + owner + mode access_mode = "public" + grantee:read  @rls maps select
  permission serve =             owner + mode access_mode = "public" + grantee:read  @check
}`

func TestCheckLayer_ServeAccessor(t *testing.T) {
	s, err := Parse(checkLayerSpec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err) // proves @check admits owner+mode+grant (the @rls vocabulary)
	}

	surf, err := s.EmitAppSurface()
	if err != nil {
		t.Fatalf("EmitAppSurface: %v", err)
	}
	o, _ := surf.Object("doc")
	serve := o.CheckVerbSQL("serve")
	if !strings.HasPrefix(serve, "SELECT EXISTS (SELECT 1 FROM docs WHERE id = $1 AND (") {
		t.Fatalf("@check must project a compiled point-check, got: %q", serve)
	}
	// It compiles the declared terms (owner column + mode column + grant store).
	for _, frag := range []string{"owner_id", "access_mode", "dacl"} {
		if !strings.Contains(serve, frag) {
			t.Errorf("serve point-check missing %q term:\n%s", frag, serve)
		}
	}

	src, err := s.EmitFramework("authz")
	if err != nil {
		t.Fatalf("EmitFramework: %v", err)
	}
	for _, want := range []string{
		"func (docAccess) CanServe(ctx context.Context, q demesne.Querier, id string) (Decision, error)",
		`case "doc.serve":`, // generic Check(object, verb, id) routes the @check verb
	} {
		if !strings.Contains(src, want) {
			t.Errorf("generated framework missing %q", want)
		}
	}

	// The TS accessor emit mirrors Go, so client/edge consumers get canServe too.
	ts, err := s.EmitFrameworkTS()
	if err != nil {
		t.Fatalf("EmitFrameworkTS: %v", err)
	}
	if !strings.Contains(ts, "canServe") {
		t.Errorf("TS framework missing canServe accessor")
	}
}

// A @check permission emits a point-check, not a policy, so it must not map a table op.
func TestCheckLayer_RejectsMaps(t *testing.T) {
	bad := strings.Replace(checkLayerSpec,
		`permission serve =             owner + mode access_mode = "public" + grantee:read  @check`,
		`permission serve =             owner + mode access_mode = "public" + grantee:read  @check maps select`, 1)
	s, err := Parse(bad)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err == nil {
		t.Fatal("expected a validation error for a @check permission that also maps a table op")
	} else if !strings.Contains(err.Error(), "@check") {
		t.Errorf("error should explain the @check/maps conflict, got: %v", err)
	}
}
