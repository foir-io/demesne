package demesne

import (
	"strings"
	"testing"
)

// The accessor enumerator has two SHAPES — a pure `+` chain unions per-relation
// branches, an `and`/`not` tree composes one SQL expression — and for a long
// time it had two PATHS. The tree shape returned early and skipped everything
// the flat shape did afterwards, so two things that have nothing to do with a
// permission's shape were silently lost whenever an `and` appeared: the ROLE
// branch, and the ability to carry a COMPOSITION relation at all.
//
// Both belong to the object, not to the expression. These pin them to the tail
// both shapes share.

const onePathSpec = `
topology { level tenant }
vocabulary v { permission doc:read }
rolestore admin {
  assignments role_assignments
  kind        principal_kind = "admin"
  subject     principal_id
  scope       tenant_id
  rolejoin    role_id roles id key
  revoked     revoked_at
}
subject member { anchor tenant reach self identifies member_id roles configurable v binds owner }
object doc {
  table docs
  scoped tenant
  relation owner:   member via member_id
  relation grantee: member via grant resource_acl(resource_id, principal_kind, principal_id, access) where resource_type = "doc" tracked
  relation parent:  doc via composition doc_edges(child_id, parent_id) where kind = "composition"
  permission view = PERMBODY   @rls maps select
}`

func onePathDefiners(t *testing.T, body string) map[string]GenFn {
	t.Helper()
	sp := validSpec(t, strings.Replace(onePathSpec, "PERMBODY", body, 1))
	fns, _ := claimDefiners(t, sp)
	return fns
}

// The role branch survives an `and` anywhere in the permission.
//
// This is the defect the unification closed, and it was silent: the listing
// simply stopped naming role holders, which is the under-reporting direction
// the whole enumerator exists to avoid. The two bodies admit the same people —
// the `and @kind("member")` narrows a branch that already only admits members —
// so any difference between them is the path, not the permission.
func TestOnePath_RoleBranchSurvivesAnAnd(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"flat", `@app_scope + owner + grantee:read`},
		{"tree", `@app_scope + owner + (grantee:read and @kind("member"))`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fns := onePathDefiners(t, tc.body)
			var body string
			for n, f := range fns {
				if strings.Contains(n, "accessors") && !strings.Contains(n, "_direct_") {
					body = f.Body
				}
			}
			if body == "" {
				t.Fatal("no enumerator emitted at all — the fixture is wrong and nothing below measures the path")
			}
			if !strings.Contains(body, "'role'::text") {
				t.Errorf("the role branch is missing on the %s shape. It is gated on the object's "+
					"rolestore and its use of @app_scope, neither of which the permission's shape "+
					"changes:\n%s", tc.name, body)
			}
		})
	}
}

// A composition relation works on both shapes, and keeps its direct/full split.
//
// The split is what keeps composition free of recursion — the full enumerator
// joins LATERAL onto <table>_direct_accessors — so it is a property of the
// relation. The tree shape could not carry one at all before: the walk refused
// it, and the object failed validation.
func TestOnePath_CompositionWorksOnBothShapes(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"flat", `@app_scope + owner + grantee:read + parent`},
		{"tree", `@app_scope + owner + (grantee:read and @kind("member")) + parent`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fns := onePathDefiners(t, tc.body)
			if _, ok := fns["docs_direct_accessors"]; !ok {
				t.Fatalf("the %s shape lost the direct/full split, which is what keeps a "+
					"composition enumerator free of recursion", tc.name)
			}
			var full GenFn
			for n, f := range fns {
				if strings.Contains(n, "accessors") && !strings.Contains(n, "_direct_") {
					full = f
				}
			}
			if !strings.Contains(full.Body, "docs_direct_accessors(e.parent_id)") {
				t.Errorf("the %s shape did not carry the composition arm:\n%s", tc.name, full.Body)
			}
		})
	}
}

// The control. A composition nested in an `and` must STILL refuse: the tail
// adds it as a union arm afterwards, and a union arm is not an intersection, so
// emitting one there would be quietly wrong rather than merely incomplete.
func TestOnePath_CompositionInsideAnAndStillRefuses(t *testing.T) {
	sp := mustSpec(t, strings.Replace(onePathSpec, "PERMBODY",
		`@app_scope + owner + (parent and @kind("member"))`, 1))
	if err := Validate(sp); err == nil {
		t.Fatal("a composition INSIDE an `and` must still fail closed — the tail can only add a " +
			"union arm, which would silently widen the intersection the permission asked for")
	}
}
