package demesne

import (
	"strings"
	"testing"
)

const holdsTermSpec = holdsSpec + `
object doc {
  table  docs
  scoped tenant > team
  permission view    = @holds("docs:read")    @rls maps select
  permission publish = @holds(docs:publish)   @rls maps update
  permission serve   = @holds("docs:read")    @check
}
object tenant_settings {
  table  tenant_settings
  scoped tenant
  permission edit = @holds("admin:write") @rls maps update
}
`

func TestHoldsTerm_ParseAndString(t *testing.T) {
	s := mustParseHolds(t, holdsTermSpec)
	var doc *Object
	for _, o := range s.Objects {
		if o.Name == "doc" {
			doc = o
		}
	}
	if doc == nil {
		t.Fatal("object doc not parsed")
	}
	byVerb := map[string]*Perm{}
	for _, pm := range doc.Perms {
		byVerb[pm.Verb] = pm
	}
	view := byVerb["view"].Expr[0]
	if view.Builtin != "holds" || view.HoldsPerm != "docs:read" {
		t.Errorf("view term = %+v, want @holds(docs:read)", view)
	}
	pub := byVerb["publish"].Expr[0]
	if pub.Builtin != "holds" || pub.HoldsPerm != "docs:publish" {
		t.Errorf("unquoted perm-key arg: got %+v, want @holds(docs:publish)", pub)
	}
	if got := pub.String(); got != "@holds(docs:publish)" {
		t.Errorf("Term.String() = %q, want @holds(docs:publish)", got)
	}
	if len(byVerb["view"].Tree.Leaves()) != 1 {
		t.Errorf("tree and expr must agree on the @holds leaf")
	}
}

func TestHoldsTerm_ParseRejectsEmptyArg(t *testing.T) {
	bad := strings.Replace(holdsTermSpec, `@holds("docs:read")    @rls`, `@holds()    @rls`, 1)
	if _, err := Parse(bad); err == nil || !strings.Contains(err.Error(), "@holds needs a permission verb") {
		t.Errorf("expected a parse error naming @holds, got %v", err)
	}
}

func TestHoldsTerm_DefinerShape(t *testing.T) {
	s := mustParseHolds(t, holdsTermSpec)
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	defs, err := s.EmitDefiners()
	if err != nil {
		t.Fatalf("emit definers: %v", err)
	}
	var fn *GenFn
	for i := range defs {
		if defs[i].Name == "member_has_perm" {
			fn = &defs[i]
		}
	}
	if fn == nil {
		t.Fatal("no member_has_perm definer generated")
	}
	if fn.Sig != "user_id text, check_tenant_id text, check_team_id text, p_perm text" {
		t.Errorf("member_has_perm sig = %q", fn.Sig)
	}
	for _, want := range []string{
		"FROM role_assignments ra JOIN roles_tbl r ON r.id = ra.role_id",
		"ra.principal_kind = 'member'",
		"ra.principal_id = user_id",
		"ra.tenant_id = check_tenant_id",
		"(ra.team_id IS NULL OR ra.team_id = check_team_id)",
		"ra.revoked_at IS NULL",
		"p_perm = ANY(r.perms)",
	} {
		if !strings.Contains(fn.Body, want) {
			t.Errorf("member_has_perm body missing %q:\n%s", want, fn.Body)
		}
	}
	if strings.Contains(fn.Body, "r.key IN") {
		t.Errorf("member_has_perm must match the permissions array, not preset keys:\n%s", fn.Body)
	}
}

func TestHoldsTerm_RLSCallShape(t *testing.T) {
	s := mustParseHolds(t, holdsTermSpec)
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	rls, err := s.EmitRLS()
	if err != nil {
		t.Fatalf("emit rls: %v", err)
	}
	sub := "(current_setting('request.jwt.claims', true)::json ->> 'sub')"

	sel := findPolicy(rls, "docs_select")
	if sel == nil {
		t.Fatalf("no docs_select policy (unsupported: %v)", rls.Unsupported)
	}
	if !strings.Contains(sel.Using, "auth.member_has_perm("+sub+", tenant_id, team_id, 'docs:read')") {
		t.Errorf("docs_select missing the full-scope @holds call:\n%s", sel.Using)
	}
	tclaim := "(current_setting('request.jwt.claims', true)::json ->> 'tenant_id')"
	if !strings.HasPrefix(sel.Using, "(tenant_id = "+tclaim+" AND ") {
		t.Errorf("@holds is a block term — containment must wrap it:\n%s", sel.Using)
	}

	upd := findPolicy(rls, "docs_update")
	if upd == nil || !strings.Contains(upd.Using, "'docs:publish'") {
		t.Errorf("docs_update should key on docs:publish: %+v", upd)
	}

	shallow := findPolicy(rls, "tenant_settings_update")
	if shallow == nil {
		t.Fatalf("no tenant_settings_update policy (unsupported: %v)", rls.Unsupported)
	}
	if !strings.Contains(shallow.Using, "auth.member_has_perm("+sub+", tenant_id, NULL, 'admin:write')") {
		t.Errorf("a tenant-scoped object must NULL-pad the deeper scope arg (only team-wide assignments confer):\n%s", shallow.Using)
	}
}

func TestHoldsTerm_CheckLayerPointCheck(t *testing.T) {
	s := mustParseHolds(t, holdsTermSpec)
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	surf, err := s.EmitAppSurface()
	if err != nil {
		t.Fatalf("EmitAppSurface: %v", err)
	}
	o, ok := surf.Object("doc")
	if !ok {
		t.Fatal("no doc surface")
	}
	serve := o.CheckVerbSQL("serve")
	if !strings.Contains(serve, "auth.member_has_perm(") || !strings.Contains(serve, "'docs:read'") {
		t.Errorf("@check point-check must compile the @holds call:\n%s", serve)
	}
}

func TestHoldsTerm_ValidateFailsClosed(t *testing.T) {
	cases := []struct {
		name string
		spec string
		want string
	}{
		{
			"verb outside the vocabulary",
			strings.Replace(holdsTermSpec, `@holds("docs:read")    @rls`, `@holds("ghost:verb")    @rls`, 1),
			`@holds("ghost:verb"), which is not a permission of vocabulary "roles"`,
		},
		{
			"rolestore without a permissions column",
			strings.Replace(holdsTermSpec, "  permissions perms\n", "", 1),
			"declares no `permissions` column",
		},
		{
			"holds inside a @pdp permission",
			holdsSpec + `
object doc {
  table  docs
  scoped tenant > team
  permission audit = @holds("docs:read") @pdp maps docs:read
}
`,
			"inside a @pdp permission",
		},
		{
			"holds on a global object",
			holdsSpec + `
object flag {
  table  flags
  scoped org
  permission view = @holds("docs:read") @rls maps select
}
`,
			"global object",
		},
		{
			"empty verb",
			strings.Replace(holdsTermSpec, `@holds("docs:read")    @rls`, `@holds("")    @rls`, 1),
			"empty verb",
		},
		{
			"no rolestore in the spec",
			`
topology { level org virtual  level tenant parent org }
vocabulary v { permission a:b preset p @ tenant = a:b }
subject admin { anchor tenant; reach descendants; identifies sub; roles configurable v; binds admin }
object t { table ts scoped tenant permission view = @holds("a:b") @rls maps select }
`,
			"declares no rolestore",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, err := Parse(c.spec)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			err = Validate(s)
			if err == nil {
				t.Fatal("expected a validation error")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error should contain %q, got:\n%v", c.want, err)
			}
		})
	}
}

func TestHoldsTerm_PDPCanNeverVacuous(t *testing.T) {
	pm := &Perm{Verb: "audit", Expr: []*Term{{Builtin: "holds", HoldsPerm: "docs:read"}}}

	g := &fwGen{}
	g.pdpCan("xAccess", pm)
	if !strings.Contains(g.b.String(), `held.Holds("docs:read")`) {
		t.Errorf("pdpCan must key on the @holds verb, not emit a vacuous Allow:\n%s", g.b.String())
	}

	ts := (&fwTSGen{}).pdpCanTS("canAudit", pm)
	if !strings.Contains(ts, `held.holds("docs:read")`) {
		t.Errorf("pdpCanTS must key on the @holds verb, not emit a vacuous Allow:\n%s", ts)
	}
}

func holdsTermSchema(permsType string) *Schema {
	sc := NewSchema()
	for _, c := range []string{"tenant_id", "team_id"} {
		sc.AddColumn("docs", c, "text", false)
	}
	sc.AddColumn("tenant_settings", "tenant_id", "text", false)
	for _, c := range []string{"principal_kind", "principal_id", "role_id", "revoked_at", "tenant_id", "team_id"} {
		sc.AddColumn("role_assignments", c, "text", true)
	}
	sc.AddColumn("roles_tbl", "id", "text", false)
	sc.AddColumn("roles_tbl", "key", "text", false)
	sc.AddColumn("roles_tbl", "perms", permsType, true)
	return sc
}

func TestHoldsTerm_SchemaRequiresArrayPermsCol(t *testing.T) {
	s := mustParseHolds(t, holdsTermSpec)
	if err := s.ValidateAgainst(holdsTermSchema("ARRAY")); err != nil {
		t.Errorf("array perms column should bind: %v", err)
	}
	err := s.ValidateAgainst(holdsTermSchema("jsonb"))
	if err == nil || !strings.Contains(err.Error(), "not an array") {
		t.Errorf("a jsonb perms column would mis-compile `= ANY` — expected a schema error, got %v", err)
	}

	noHolds := mustParseHolds(t, holdsSpec+`
object doc {
  table  docs
  scoped tenant > team
  permission view = @scoped @rls maps select
}
object tenant_settings {
  table  tenant_settings
  scoped tenant
  permission view = @scoped @rls maps select
}
`)
	if err := noHolds.ValidateAgainst(holdsTermSchema("jsonb")); err != nil {
		t.Errorf("without @holds the perms column type is not constrained: %v", err)
	}
}
