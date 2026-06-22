package demesne

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadAgnostic(t *testing.T) *Spec {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("examples", "agnostic.demesne"))
	if err != nil {
		t.Fatalf("read agnostic example: %v", err)
	}
	s, err := Parse(string(src))
	if err != nil {
		t.Fatalf("parse agnostic example: %v", err)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("validate agnostic example: %v", err)
	}
	return s
}

func TestAgnostic_ScopeClaimDecoupling(t *testing.T) {
	s := loadAgnostic(t)
	res, err := s.EmitRLS()
	if err != nil {
		t.Fatalf("emit: %v", err)
	}

	asset := findPolicy(res, "assets_select")
	if asset == nil {
		t.Fatalf("no assets_select (unsupported: %v)", res.Unsupported)
	}
	for _, frag := range []string{

		"tenant_ref = " + s.claim("tnt"),
		"space_ref = " + s.claim("spc"),

		"holder_ref = " + s.claim("member_ref"),

		s.claim("spc") + " IS NULL",
	} {
		if !strings.Contains(asset.Using, frag) {
			t.Errorf("assets_select missing %q in:\n%s", frag, asset.Using)
		}
	}

	for _, leaked := range []string{
		s.claim("tenant_id"), s.claim("space_id"), s.claim("tenant_ref"),
	} {
		if strings.Contains(asset.Using, leaked) {
			t.Errorf("assets_select leaked a conventional claim %q:\n%s", leaked, asset.Using)
		}
	}

	space := findPolicy(res, "spaces_select")
	if space == nil {
		t.Fatal("no spaces_select policy")
	}
	for _, frag := range []string{
		"space_pk = " + s.claim("spc"),
		"tenant_ref = " + s.claim("tnt"),
		"tenant_ref, space_pk)",
	} {
		if !strings.Contains(space.Using, frag) {
			t.Errorf("spaces_select missing %q in:\n%s", frag, space.Using)
		}
	}

	contract, err := s.ClaimsContract()
	if err != nil {
		t.Fatal(err)
	}
	set := map[string]bool{}
	for _, c := range contract {
		set[c] = true
	}
	for _, want := range []string{"tnt", "spc", "sub", "member_ref"} {
		if !set[want] {
			t.Errorf("claims contract missing %q: %v", want, contract)
		}
	}
	for _, bad := range []string{"tenant_id", "space_id", "tenant_ref", "space_ref", "platform_id"} {
		if set[bad] {
			t.Errorf("claims contract leaked a conventional/column key %q: %v", bad, contract)
		}
	}
}

func TestAgnostic_NonIDPrimaryKey(t *testing.T) {
	s := loadAgnostic(t)

	pc, err := s.PointCheckSQL("asset")
	if err != nil {
		t.Fatal(err)
	}
	if pc != "SELECT EXISTS (SELECT 1 FROM assets WHERE asset_pk = $1)" {
		t.Errorf("PointCheckSQL not over the declared PK: %s", pc)
	}

	res, err := s.EmitRLS()
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	asset := findPolicy(res, "assets_select")
	if asset == nil || !strings.Contains(asset.Using, "assets.asset_pk, 'read')") {
		t.Errorf("grant fragment must reference assets.asset_pk:\n%v", asset)
	}

	defs, err := s.EmitDefiners()
	if err != nil {
		t.Fatalf("emit definers: %v", err)
	}
	var kernel *GenFn
	for i := range defs {
		if defs[i].Name == "member_can_access_asset" {
			kernel = &defs[i]
		}
	}
	if kernel == nil {
		t.Fatal("no member_can_access_asset kernel definer")
	}
	if !strings.Contains(kernel.Body, "r.asset_pk = p_asset_id") {
		t.Errorf("kernel gate must match on the declared PK:\n%s", kernel.Body)
	}
	if strings.Contains(kernel.Body, "r.id = ") {
		t.Errorf("kernel gate still assumes an `id` PK:\n%s", kernel.Body)
	}

	surf, err := s.ResourceAccessSurface("asset")
	if err != nil {
		t.Fatalf("resource access surface: %v", err)
	}
	if got := surf.ModeSQL(); !strings.HasSuffix(got, "WHERE asset_pk = $1") {
		t.Errorf("ModeSQL not over the declared PK: %s", got)
	}
	if got := surf.SetVisibilitySQL(); !strings.HasSuffix(got, "WHERE asset_pk = $2") {
		t.Errorf("SetVisibilitySQL not over the declared PK: %s", got)
	}

	if !eqStrs(surf.ScopeCols, []string{"tenant_ref", "space_ref"}) {
		t.Errorf("access surface scope cols = %v, want [tenant_ref space_ref]", surf.ScopeCols)
	}
}

func TestAgnostic_ForwardIsolation(t *testing.T) {
	s := loadAgnostic(t)
	res, err := s.EmitRLS()
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	asset := findPolicy(res, "assets_select")
	if asset == nil {
		t.Fatal("no assets_select")
	}

	containment := "tenant_ref = " + s.claim("tnt") + " AND space_ref = " + s.claim("spc")
	if !strings.Contains(asset.Using, containment) {
		t.Errorf("assets_select containment not the expected sargable AND-chain %q in:\n%s", containment, asset.Using)
	}

	if !strings.Contains(asset.Using, "auth.is_ops("+s.claim("sub")+") AND "+s.claim("spc")+" IS NULL") {
		t.Errorf("operator branch must be scope-gated (no ambient cross-tenant reach):\n%s", asset.Using)
	}

	rng := rand.New(rand.NewSource(0x2778))
	for iter := 0; iter < 500; iter++ {
		spec := genCustomNamedSpec(rng)
		for _, sub := range spec.Subjects {
			cols, virtual, err := spec.PinnedColumns(sub)
			if err != nil {
				t.Fatalf("iter %d PinnedColumns(%s): %v", iter, sub.Name, err)
			}

			if (len(cols) == 0) != virtual {
				t.Fatalf("iter %d subject %s: empty-pin %v must equal virtual-anchor %v", iter, sub.Name, cols == nil, virtual)
			}
			if virtual {
				continue
			}

			want := spec.Topology.LevelByName(sub.Anchor).claimKey()
			if cols[len(cols)-1] != want {
				t.Fatalf("iter %d subject %s deepest pin %q, want anchor claim key %q", iter, sub.Name, cols[len(cols)-1], want)
			}
		}

		res, err := spec.EmitRLS()
		if err != nil {
			t.Fatalf("iter %d emit: %v", iter, err)
		}
		pol := findPolicy(res, "rows_select")
		if pol == nil {
			t.Fatalf("iter %d: no rows_select (unsupported %v)", iter, res.Unsupported)
		}
		for _, l := range spec.Topology.Levels {
			if l.Virtual {
				continue
			}
			want := l.scopeColumn() + " = " + spec.claim(l.claimKey())
			if !strings.Contains(pol.Using, want) {
				t.Fatalf("iter %d: rows_select missing custom-named containment %q in:\n%s", iter, want, pol.Using)
			}
		}
	}
}

func genCustomNamedSpec(rng *rand.Rand) *Spec {
	depth := 2 + rng.Intn(3)
	virtualRoot := rng.Intn(2) == 0
	top := &Topology{}
	names := make([]string, depth)
	for i := 0; i < depth; i++ {
		names[i] = fmt.Sprintf("l%d", i)
		lv := &Level{Name: names[i]}
		if i == 0 {
			lv.Virtual = virtualRoot
		} else {
			lv.Parents = []string{names[i-1]}
		}
		if !lv.Virtual {
			lv.ScopeCol = names[i] + "_fk"
			lv.ClaimKey = names[i] + "_k"
		}
		top.Levels = append(top.Levels, lv)
	}
	s := &Spec{Topology: top}
	for i := 0; i < depth; i++ {
		for _, reach := range []string{"self", "descendants"} {
			s.Subjects = append(s.Subjects, &Subject{
				Name: fmt.Sprintf("s%d_%s", i, reach), Anchor: names[i], Reach: reach, Identifies: "sub",
			})
		}
	}

	var scoped []string
	for _, l := range top.Levels {
		if !l.Virtual {
			scoped = append(scoped, l.Name)
		}
	}
	leaf := names[depth-1]
	s.Objects = []*Object{{
		Name: "row", Table: "rows", PK: "row_pk", Scoped: scoped,
		Perms: []*Perm{{
			Verb: "view", Maps: "select", Layers: []string{"rls"},
			Tree: &PermNode{Op: "leaf", Term: &Term{Builtin: "scoped"}},
			Expr: []*Term{{Builtin: "scoped"}},
		}},
	}}
	_ = leaf
	return s
}

func TestAgnostic_BindsToSchema(t *testing.T) {
	s := loadAgnostic(t)
	sc := agnosticSchema()
	if err := s.ValidateAgainst(sc); err != nil {
		t.Fatalf("agnostic spec should bind to its matching schema, got: %v", err)
	}

	delete(sc.tables["assets"], "asset_pk")
	if err := s.ValidateAgainst(sc); err == nil || !strings.Contains(err.Error(), `no column "asset_pk"`) {
		t.Errorf("missing declared PK should be reported, got: %v", err)
	}
}

func TestAgnostic_GrammarBindsKnobs(t *testing.T) {
	s := loadAgnostic(t)

	tenant := s.Topology.LevelByName("tenant")
	if tenant.ScopeCol != "tenant_ref" || tenant.ClaimKey != "tnt" {
		t.Errorf("tenant level knobs = (%q,%q), want (tenant_ref,tnt)", tenant.ScopeCol, tenant.ClaimKey)
	}
	space := s.Topology.LevelByName("space")
	if space.ScopeCol != "space_ref" || space.ClaimKey != "spc" {
		t.Errorf("space level knobs = (%q,%q), want (space_ref,spc)", space.ScopeCol, space.ClaimKey)
	}

	if o := findObject(s, "asset"); o == nil || o.PK != "asset_pk" {
		t.Errorf("asset.PK = %q, want asset_pk", o.PK)
	}
	if o := findObject(s, "space"); o == nil || o.PK != "space_pk" {
		t.Errorf("space.PK = %q, want space_pk", o.PK)
	}

	d := mustSpec(t, `
		topology { level tenant level project parent tenant }
		subject admin { anchor tenant reach descendants identifies sub roles none }
		object doc { table docs scoped tenant > project
		  relation t: tenant via tenant_id
		  permission view = @scoped @rls maps select }`)
	if got := d.Topology.LevelByName("project").scopeColumn(); got != "project_id" {
		t.Errorf("default scopeColumn = %q, want project_id", got)
	}
	if got := d.Topology.LevelByName("project").claimKey(); got != "project_id" {
		t.Errorf("default claimKey = %q, want project_id", got)
	}
	if got := findObject(d, "doc").pk(); got != "id" {
		t.Errorf("default object pk = %q, want id", got)
	}
}

func agnosticSchema() *Schema {
	sc := NewSchema()
	for _, c := range []string{"asset_pk", "tenant_ref", "space_ref", "holder_ref", "share"} {
		sc.AddColumn("assets", c, "text", c == "share")
	}
	for _, c := range []string{"space_pk", "tenant_ref"} {
		sc.AddColumn("spaces", c, "text", false)
	}
	for _, c := range []string{"member_kind", "member_ref", "role_ref", "killed_at", "tenant_ref", "space_ref"} {
		sc.AddColumn("crew_grants", c, "text", c == "killed_at")
	}
	sc.AddColumn("crew_roles", "row_id", "text", false)
	sc.AddColumn("crew_roles", "slug", "text", false)
	for _, c := range []string{"asset_ref", "grantee_kind", "grantee_ref", "perm"} {
		sc.AddColumn("asset_acl", c, "text", false)
	}
	sc.AddColumn("ops_users", "user_ref", "text", false)
	sc.AddColumn("ops_users", "is_ops", "boolean", false)
	sc.AddColumn("ops_users", "state", "text", false)
	return sc
}
