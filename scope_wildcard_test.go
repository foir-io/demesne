package demesne

import (
	"strings"
	"testing"
)

const scopeWildcardSpec = `
topology { level platform virtual level tenant parent platform level project parent tenant }
vocabulary v { permission members:read preset padmin @ project = members:read preset tadmin @ tenant = members:read rank tadmin > padmin }
rolestore admin {
  assignments role_assignments
  kind        principal_kind = "admin"
  subject     principal_id
  scope       tenant_id project_id
  rolejoin    role_id roles id key
  revoked     revoked_at
  permissions permissions
}
subject admin { anchor tenant reach descendants identifies sub roles configurable v binds admin }
object pinned {
  table  pinned_rows
  scoped tenant > project
  permission view = @holds(members:read) @rls maps select
}
object spanning {
  table  spanning_rows
  scoped tenant > project wildcard
  permission view = @holds(members:read) @rls maps select
}
`

func wildcardPolicy(t *testing.T, s *Spec, table, cmd string) string {
	t.Helper()
	rls, err := s.EmitRLS()
	if err != nil {
		t.Fatalf("EmitRLS: %v", err)
	}
	for _, p := range rls.Policies {
		if p.Table == table && p.Cmd == cmd {
			return p.Using + p.Check
		}
	}
	t.Fatalf("no %s policy on %s", cmd, table)
	return ""
}

func TestScopeWildcard_ContainmentIsNullSafe(t *testing.T) {
	s := mustSpec(t, scopeWildcardSpec)
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}

	claim := "(current_setting('request.jwt.claims', true)::json ->> 'project_id')"

	pinned := wildcardPolicy(t, s, "pinned_rows", "SELECT")
	if !strings.Contains(pinned, "project_id = "+claim) {
		t.Fatalf("control: an undeclared scope level must still emit the bare equality:\n%s", pinned)
	}
	if strings.Contains(pinned, "project_id IS NULL") {
		t.Errorf("an undeclared scope level must NOT become NULL-safe:\n%s", pinned)
	}

	spanning := wildcardPolicy(t, s, "spanning_rows", "SELECT")
	want := "(project_id IS NULL OR project_id = " + claim + ")"
	if !strings.Contains(spanning, want) {
		t.Errorf("`project wildcard` must emit %s in the containment conjunct:\n%s", want, spanning)
	}
}

func TestScopeWildcard_NarrowsNothingElse(t *testing.T) {
	s := mustSpec(t, scopeWildcardSpec)
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	spanning := wildcardPolicy(t, s, "spanning_rows", "SELECT")

	if !strings.Contains(spanning, "tenant_id = (current_setting('request.jwt.claims', true)::json ->> 'tenant_id')") {
		t.Errorf("the tenant conjunct must be untouched — a wildcard project must not escape its tenant:\n%s", spanning)
	}
	if strings.Contains(spanning, "tenant_id IS NULL") {
		t.Errorf("only the marked level may become NULL-safe:\n%s", spanning)
	}
	if !strings.Contains(spanning, "auth.admin_has_perm") {
		t.Errorf("the authority conjunct must survive — a wildcard scope is containment, not permission:\n%s", spanning)
	}
}

func TestScopeWildcard_AppliesToEveryCommand(t *testing.T) {
	src := strings.Replace(scopeWildcardSpec,
		"permission view = @holds(members:read) @rls maps select\n}\n",
		"permission view = @holds(members:read) @rls maps select\n  permission create = @holds(members:read) @rls maps insert\n}\n", 2)
	s := mustSpec(t, src)
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	ins := wildcardPolicy(t, s, "spanning_rows", "INSERT")
	if !strings.Contains(ins, "(project_id IS NULL OR project_id = ") {
		t.Errorf("the WITH CHECK on INSERT must carry the same NULL-safe conjunct, or a row the SELECT policy admits cannot be written:\n%s", ins)
	}
}

func TestScopeWildcard_RejectedWhereItCannotBind(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "virtual level",
			src: `
topology { level platform virtual level tenant parent platform }
subject admin { anchor tenant reach descendants identifies sub roles none binds admin }
object global { table globals scoped platform wildcard permission view = @public @rls maps select }
`,
			want: "could never narrow or widen anything",
		},
		{
			name: "the object's own level",
			src: `
topology { level tenant level project parent tenant }
subject admin { anchor tenant reach descendants identifies sub roles none binds admin }
object project { table projects pk id level project scoped tenant > project wildcard permission view = @public @rls maps select }
`,
			want: "a primary key is never NULL",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := Parse(tc.src)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			err = Validate(s)
			if err == nil {
				t.Fatalf("expected a validation error naming %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error must explain why the marker cannot bind (want %q): %v", tc.want, err)
			}
		})
	}
}

func TestScopeWildcard_AppSurfaceCarriesIt(t *testing.T) {
	src := strings.Replace(scopeWildcardSpec,
		"permission view = @holds(members:read) @rls maps select\n}\n",
		"permission view = @holds(members:read) @rls maps select\n  permission edit = @holds(members:read) @rls maps update\n}\n", 2)
	s := mustSpec(t, src)
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	surface, err := s.EmitAppSurface()
	if err != nil {
		t.Fatalf("EmitAppSurface: %v", err)
	}
	for _, o := range surface.Objects {
		if o.Table != "spanning_rows" {
			continue
		}
		sql := o.EditCheckSQL
		if sql == "" {
			t.Fatal("no point-check SQL on spanning_rows — the parity assertion below would be vacuous")
		}
		if !strings.Contains(sql, "(project_id IS NULL OR project_id = ") {
			t.Errorf("the point-check the app surface runs must carry the same conjunct the policy does, "+
				"or CanEdit and the floor disagree about a wildcard row:\n%s", sql)
		}
		return
	}
	t.Fatal("no app surface for spanning_rows")
}

func TestScopeWildcard_AbsentByDefault(t *testing.T) {
	s := mustSpec(t, scopeWildcardSpec)
	for _, o := range s.Objects {
		if o.Name == "pinned" && len(o.ScopeWildcards) != 0 {
			t.Errorf("object %q parsed a wildcard it does not declare: %v", o.Name, o.ScopeWildcards)
		}
		if o.Name == "spanning" {
			if len(o.ScopeWildcards) != 1 || o.ScopeWildcards[0] != "project" {
				t.Errorf("object %q: want ScopeWildcards [project], got %v", o.Name, o.ScopeWildcards)
			}
			if len(o.Scoped) != 2 || o.Scoped[0] != "tenant" || o.Scoped[1] != "project" {
				t.Errorf("the marker must not disturb the scope chain: %v", o.Scoped)
			}
		}
	}
}
