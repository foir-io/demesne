package demesne

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// loadExample parses + validates the worked-example spec — the engine's positive
// end-to-end fixture. (Full byte-for-byte acceptance against a live database is a
// platform's oracle job; here we prove the language + every emitter on one
// complete, self-contained spec.)
func loadExample(t *testing.T) *Spec {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("examples", "example.demesne"))
	if err != nil {
		t.Fatalf("read example: %v", err)
	}
	s, err := Parse(string(src))
	if err != nil {
		t.Fatalf("parse example: %v", err)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("validate example: %v", err)
	}
	return s
}

// TestExample_ParseAndShape — the worked example parses, validates, and yields
// the AST shape the emitters depend on.
func TestExample_ParseAndShape(t *testing.T) {
	s := loadExample(t)

	if s.Topology == nil || len(s.Topology.Levels) != 3 {
		t.Fatalf("topology: want 3 levels, got %v", s.Topology)
	}
	if l := s.Topology.Levels[0]; l.Name != "org" || !l.Virtual {
		t.Errorf("level[0]: want virtual root 'org', got %+v", l)
	}

	staff := findVocab(s, "staff")
	if staff == nil {
		t.Fatal("missing staff vocabulary")
	}
	if owner := findPreset(staff, "tenant_owner"); owner == nil || !owner.Star {
		t.Errorf("tenant_owner preset: want star bundle, got %+v", owner)
	}
	if !eqStrs(staff.Rank, []string{"tenant_owner", "ws_editor", "ws_viewer"}) {
		t.Errorf("staff rank: got %v", staff.Rank)
	}

	root := findSubject(s, "root")
	if root == nil || root.Membership == nil || root.Membership.FlagCol != "is_root" ||
		root.Membership.Table != "staff_users" || root.Membership.ActiveVal != "ACTIVE" {
		t.Errorf("root membership: %+v", root)
	}

	doc := findObject(s, "doc")
	if doc == nil {
		t.Fatal("missing doc object")
	}
	// The doc's access is composed from plain relations + terms (no descriptor).
	if r := findRelation(doc, "owner"); r == nil {
		t.Fatal("doc.owner relation missing")
	} else if vc, ok := r.Repr.(ViaColumn); !ok || vc.Column != "owner_id" {
		t.Errorf("doc.owner repr: %#v", r.Repr)
	}
	if r := findRelation(doc, "grantee"); r == nil {
		t.Fatal("doc.grantee relation missing")
	} else if vg, ok := r.Repr.(ViaGrant); !ok || vg.Table != "doc_acl" || vg.RecordCol != "doc_id" {
		t.Errorf("doc.grantee grant edge: %#v", r.Repr)
	}
	// The read permission carries the two public visibility mode terms.
	view := findPerm(doc, "view")
	if view == nil {
		t.Fatal("doc.view permission missing")
	}
	var modes []string
	for _, term := range view.Expr {
		if term.ModeCol == "visibility" {
			modes = append(modes, term.ModeVal)
		}
	}
	if !eqStrs(modes, []string{"public_project", "public_world"}) {
		t.Errorf("doc.view visibility mode terms: %v", modes)
	}

	ws := findObject(s, "workspace")
	if r := findRelation(ws, "admin"); r == nil {
		t.Fatal("workspace.admin relation missing")
	} else if vr, ok := r.Repr.(ViaRole); !ok || !vr.HasRank || vr.RankMin != "ws_editor" {
		t.Errorf("workspace.admin: want role(rank>=ws_editor), got %#v", r.Repr)
	}
	if p := findPerm(doc, "publish"); p == nil || !eqStrs(p.Layers, []string{"pdp"}) {
		t.Errorf("doc.publish should be @pdp, got %+v", p)
	}
}

// TestExample_EmitRLS — the level-entity (workspace) and the descriptor object
// (doc) both emit, with the operator branch, the role definers, and the
// descriptor terms (public modes read-only, the acl-grant definer tail).
func TestExample_EmitRLS(t *testing.T) {
	s := loadExample(t)
	res, err := s.EmitRLS()
	if err != nil {
		t.Fatalf("emit: %v", err)
	}

	ws := findPolicy(res, "workspaces_select")
	if ws == nil {
		t.Fatalf("no workspaces_select (unsupported: %v)", res.Unsupported)
	}
	for _, frag := range []string{
		"auth.is_root(" + cSub + ")",
		// The admin plane subject is named `staff`, so the role-definer affixes are
		// is_<level>_staff / staff_has_<obj>_role — not a baked "admin" (EID-265 WS2).
		"auth.is_tenant_staff(" + cSub + ", tenant_id)",
		"auth.staff_has_workspace_role(" + cSub + ", tenant_id, id)",
	} {
		if !strings.Contains(ws.Using, frag) {
			t.Errorf("workspaces_select missing %q in:\n%s", frag, ws.Using)
		}
	}

	sel := findPolicy(res, "docs_select")
	if sel == nil {
		t.Fatal("no docs_select policy")
	}
	for _, frag := range []string{
		"owner_id = " + cMember,
		"visibility = 'public_project'",
		"visibility = 'public_world'",
		"auth.doc_acl_grants(" + cMember + ", docs.id, 'read')",
	} {
		if !strings.Contains(sel.Using, frag) {
			t.Errorf("docs_select missing %q in:\n%s", frag, sel.Using)
		}
	}
	// Insert drops the public/acl read terms (you create your own rows).
	ins := findPolicy(res, "docs_insert")
	if ins == nil || ins.Cmd != "INSERT" || strings.Contains(ins.Check, "public_world") {
		t.Errorf("docs_insert shape wrong: %+v", ins)
	}
}

// TestExample_EmitDefiners — the compiler owns the full SECURITY DEFINER surface:
// membership, the role plane, the realtime kernel gate, and the descriptor grants.
func TestExample_EmitDefiners(t *testing.T) {
	s := loadExample(t)
	defs, err := s.EmitDefiners()
	if err != nil {
		t.Fatalf("emit definers: %v", err)
	}
	got := map[string]bool{}
	for _, d := range defs {
		got[d.Name] = true
		if !strings.Contains(d.CreateSQL(), "SECURITY DEFINER") {
			t.Errorf("definer %q is not SECURITY DEFINER", d.Name)
		}
	}
	for _, want := range []string{
		"is_root", "is_tenant_staff", "staff_has_workspace_role",
		// The doc's owner principal is `member`, so the realtime gate is named for
		// it — NOT an assumed `customer` (EID-265 WS2 principal-kinds generalization).
		"is_ws_editor", "member_can_access_doc", "doc_acl_grants",
	} {
		if !got[want] {
			t.Errorf("missing generated definer %q; got %v", want, keys(got))
		}
	}
}

// TestExample_EmitPDP — the staff procedures compile to the admin PDP map, the
// healthz call is ungoverned, and RenderGo is deterministic.
func TestExample_EmitPDP(t *testing.T) {
	s := loadExample(t)
	pdps, err := s.EmitPDP()
	if err != nil {
		t.Fatalf("emit pdp: %v", err)
	}
	// The emit-site is the vocabulary name; the staff vocab → the app PDP.
	admin := pdps["staff"]
	if admin == nil {
		t.Fatal("no staff PDP emit-site")
	}
	if admin.Policy["docs.v1.DocService/CreateDoc"] != "docs:write" {
		t.Errorf("CreateDoc → %q", admin.Policy["docs.v1.DocService/CreateDoc"])
	}
	if _, ok := admin.Ungoverned["meta.v1.MetaService/Healthz"]; !ok {
		t.Error("Healthz should be ungoverned")
	}
	src := admin.RenderGo("Policy")
	if !strings.Contains(src, `"docs.v1.DocService/CreateDoc": "docs:write",`) {
		t.Errorf("RenderGo missing CreateDoc:\n%s", src)
	}
}

// TestExample_ClaimsContract — virtual levels contribute no column; tenant and
// workspace do, and the subjects add sub + member_id.
func TestExample_ClaimsContract(t *testing.T) {
	s := loadExample(t)
	contract, err := s.ClaimsContract()
	if err != nil {
		t.Fatal(err)
	}
	set := map[string]bool{}
	for _, c := range contract {
		set[c] = true
	}
	for _, want := range []string{"tenant_id", "workspace_id", "sub", "member_id"} {
		if !set[want] {
			t.Errorf("claims contract missing %q: %v", want, contract)
		}
	}
	if set["org_id"] {
		t.Errorf("claims contract leaked the virtual-root column: %v", contract)
	}
}

// TestExample_PolicySQL — the idempotent DROP+CREATE render is deterministic,
// grants the given role, and uses the emitted USING/WITH CHECK verbatim.
func TestExample_PolicySQL(t *testing.T) {
	s := loadExample(t)
	res, err := s.EmitRLS()
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	sql := res.PolicySQL("authenticated")
	if sql != res.PolicySQL("authenticated") {
		t.Fatal("PolicySQL is not deterministic")
	}
	for _, frag := range []string{
		"DROP POLICY IF EXISTS docs_select ON public.docs;",
		"CREATE POLICY docs_select ON public.docs FOR SELECT TO authenticated",
		"USING (",
		"DROP POLICY IF EXISTS docs_insert ON public.docs;",
		"CREATE POLICY docs_insert ON public.docs FOR INSERT TO authenticated",
		"WITH CHECK (",
	} {
		if !strings.Contains(sql, frag) {
			t.Errorf("PolicySQL missing %q in:\n%s", frag, sql)
		}
	}
	// A SELECT policy carries USING, never WITH CHECK.
	sel := sql[strings.Index(sql, "CREATE POLICY docs_select"):]
	sel = sel[:strings.Index(sel, ";")]
	if strings.Contains(sel, "WITH CHECK") {
		t.Errorf("SELECT policy must not have WITH CHECK:\n%s", sel)
	}
}

// TestExample_DefinersSQL — every generated definer renders as a CREATE OR
// REPLACE FUNCTION, in dependency order.
func TestExample_DefinersSQL(t *testing.T) {
	s := loadExample(t)
	defs, err := s.EmitDefiners()
	if err != nil {
		t.Fatalf("emit definers: %v", err)
	}
	sql := DefinersSQL(defs)
	if got := strings.Count(sql, "CREATE OR REPLACE FUNCTION auth."); got != len(defs) {
		t.Errorf("want %d CREATE OR REPLACE, got %d", len(defs), got)
	}
	for _, d := range defs {
		if !strings.Contains(sql, "CREATE OR REPLACE FUNCTION auth."+d.Name+"(") {
			t.Errorf("DefinersSQL missing %q", d.Name)
		}
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
