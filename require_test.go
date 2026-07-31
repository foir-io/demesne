package demesne

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func requireSpecSrc(t *testing.T) string {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("examples", "require.demesne"))
	if err != nil {
		t.Fatalf("read examples/require.demesne: %v", err)
	}
	return string(src)
}

const requireBaseSpec = `
topology { level tenant level project parent tenant }
vocabulary admin {
  permission docs:write
  preset editor @ project = docs:write
}
rolestore admin {
  assignments role_assignments
  kind        principal_kind = "admin"
  subject     principal_id
  scope       tenant_id project_id
  rolejoin    role_id roles id key
  revoked     revoked_at
  permissions permissions
}
subject admin { anchor tenant reach descendants identifies sub roles configurable admin binds admin }
object doc {
  table  docs
  scoped tenant
  relation author: admin via author_id
  permission view   = @holds(docs:write) + author @rls maps select
  permission create = @holds(docs:write)          @rls maps insert
  permission edit   = @holds(docs:write) + author @rls maps update
`

func parseRequire(t *testing.T, body string) (*Spec, error) {
	t.Helper()
	s, err := Parse(requireBaseSpec + body + "\n}\n")
	if err != nil {
		return nil, err
	}
	return s, Validate(s)
}

func mustParseRequire(t *testing.T, body string) *Spec {
	t.Helper()
	s, err := parseRequire(t, body)
	if err != nil {
		t.Fatalf("parse/validate: %v", err)
	}
	return s
}

func policyByName(t *testing.T, s *Spec, name string) Policy {
	t.Helper()
	res, err := s.EmitRLS()
	if err != nil {
		t.Fatalf("EmitRLS: %v", err)
	}
	if len(res.Unsupported) > 0 {
		t.Fatalf("unsupported: %v", res.Unsupported)
	}
	for _, p := range res.Policies {
		if p.Name == name {
			return p
		}
	}
	t.Fatalf("no policy %q in %v", name, res.Policies)
	return Policy{}
}

func TestRequire_EmitsRestrictivePolicy(t *testing.T) {
	s := mustParseRequire(t, `  require edit = @self(author_id)`)
	p := policyByName(t, s, "docs_update_require")
	if !p.Restrictive {
		t.Error("the require policy must be RESTRICTIVE")
	}
	if p.Cmd != "UPDATE" {
		t.Errorf("cmd = %q, want UPDATE", p.Cmd)
	}
	want := "author_id = (current_setting('request.jwt.claims', true)::json ->> 'sub')"
	if p.Using != want || p.Check != want {
		t.Errorf("using/check = %q / %q, want %q", p.Using, p.Check, want)
	}
	sql := mustEmitRLS(t, s).PolicySQL("authenticated")
	if !strings.Contains(sql, "CREATE POLICY docs_update_require ON public.docs AS RESTRICTIVE FOR UPDATE TO authenticated") {
		t.Errorf("PolicySQL missing the AS RESTRICTIVE clause:\n%s", sql)
	}
	if strings.Contains(sql, "CREATE POLICY docs_update ON public.docs AS RESTRICTIVE") {
		t.Error("the permissive policy must not be marked RESTRICTIVE")
	}
}

func mustEmitRLS(t *testing.T, s *Spec) *RLSResult {
	t.Helper()
	res, err := s.EmitRLS()
	if err != nil {
		t.Fatalf("EmitRLS: %v", err)
	}
	return res
}

func TestRequire_LeavesThePermissivePolicyUntouched(t *testing.T) {
	plain := mustParseRequire(t, "")
	narrowed := mustParseRequire(t, `  require edit = @self(author_id)`)
	for _, name := range []string{"docs_select", "docs_insert", "docs_update"} {
		if a, b := policyByName(t, plain, name), policyByName(t, narrowed, name); a.Using != b.Using || a.Check != b.Check {
			t.Errorf("%s changed when a require was added:\n plain:    %s | %s\n narrowed: %s | %s", name, a.Using, a.Check, b.Using, b.Check)
		}
	}
}

func TestRequire_NarrowsThePointCheckOnEverySurface(t *testing.T) {
	s := mustParseRequire(t, `  require edit = @self(author_id)`)
	surf, err := s.EmitAppSurface()
	if err != nil {
		t.Fatalf("EmitAppSurface: %v", err)
	}
	o, ok := surf.Object("doc")
	if !ok {
		t.Fatal("no doc object in the app surface")
	}
	if !strings.Contains(o.EditCheckSQL, "AND (author_id = (current_setting('request.jwt.claims', true)::json ->> 'sub'))") {
		t.Errorf("the point-check must carry the require conjunct:\n%s", o.EditCheckSQL)
	}

	gopkg, err := s.EmitFramework("authz")
	if err != nil {
		t.Fatalf("EmitFramework: %v", err)
	}
	ts, err := s.EmitFrameworkTS()
	if err != nil {
		t.Fatalf("EmitFrameworkTS: %v", err)
	}
	proj, err := s.EmitTS()
	if err != nil {
		t.Fatalf("EmitTS: %v", err)
	}
	for name, out := range map[string]string{"Go framework": gopkg, "TS framework": ts, "TS projection": proj} {
		if !strings.Contains(out, o.EditCheckSQL) {
			t.Errorf("%s does not carry the narrowed point-check — the app surface would disagree with the floor", name)
		}
	}
}

func TestRequire_CrossObjectBorrowInheritsTheNarrowing(t *testing.T) {
	src := requireBaseSpec + "  require view = @self(author_id)\n}\n" + `
object comment {
  table  comments
  scoped tenant
  relation doc: admin via object doc->view on doc_id
  permission view = doc @rls maps select
}`
	s, err := Parse(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	defs, err := s.EmitDefiners()
	if err != nil {
		t.Fatalf("EmitDefiners: %v", err)
	}
	for _, d := range defs {
		if d.Name != "doc_can_view" {
			continue
		}
		if !strings.Contains(d.Body, "AND (author_id = (current_setting('request.jwt.claims', true)::json ->> 'sub'))") {
			t.Errorf("a borrowed verb must carry its require, or the borrower over-grants:\n%s", d.Body)
		}
		return
	}
	t.Fatal("no doc_can_view definer emitted")
}

func TestRequire_WithoutAPermissionIsACompileError(t *testing.T) {
	_, err := parseRequire(t, `  require publish = @self(author_id)`)
	if err == nil {
		t.Fatal("a require naming no permission must fail to compile — a RESTRICTIVE policy alone denies everything")
	}
	if !strings.Contains(err.Error(), "denies every caller") {
		t.Errorf("error must say why it fails closed, got: %v", err)
	}
}

func TestRequire_RejectsWideningTerms(t *testing.T) {
	for _, body := range []string{
		`  require create = @scoped`,
		`  require view = @public`,
		`  require create = @open`,
	} {
		_, err := parseRequire(t, body)
		if err == nil {
			t.Errorf("%s: a widening term in a require must be rejected", body)
			continue
		}
		if !strings.Contains(err.Error(), "can only narrow") {
			t.Errorf("%s: unexpected error: %v", body, err)
		}
	}
}

func TestRequire_DuplicateClauseIsAnError(t *testing.T) {
	_, err := parseRequire(t, "  require edit = @self(author_id)\n  require edit = @holds(docs:write)")
	if err == nil || !strings.Contains(err.Error(), "more than once") {
		t.Errorf("a duplicate require must be rejected, got: %v", err)
	}
}

func TestRequire_NegationMustBeConjoined(t *testing.T) {
	_, err := parseRequire(t, `  require edit = not author`)
	if err == nil || !strings.Contains(err.Error(), "positively gated") {
		t.Errorf("a bare negation in a require must be rejected, got: %v", err)
	}
}

const requireExternalSpec = `
external predicate docs_in_tenant(text, text[])
` + requireBaseSpec + `  require create = @external(docs_in_tenant, tenant_id, tag_ids)
}
`

func TestRequire_ExternalPredicateCompilesAndCloses(t *testing.T) {
	s, err := Parse(requireExternalSpec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	p := policyByName(t, s, "docs_insert_require")
	if want := "auth.docs_in_tenant(tenant_id, tag_ids)"; p.Check != want {
		t.Errorf("check = %q, want %q", p.Check, want)
	}
	names, err := s.DefinerNames()
	if err != nil {
		t.Fatalf("DefinerNames: %v", err)
	}
	if !contains(names, "auth.docs_in_tenant") {
		t.Errorf("a declared external must appear in the definer surface the deployment owes: %v", names)
	}
}

func TestRequire_ExternalMustBeDeclared(t *testing.T) {
	src := strings.Replace(requireExternalSpec, "external predicate docs_in_tenant(text, text[])\n", "", 1)
	s, err := Parse(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	err = Validate(s)
	if err == nil || !strings.Contains(err.Error(), "no `external predicate docs_in_tenant(...)` declaration") {
		t.Errorf("an undeclared external must be rejected, got: %v", err)
	}
}

func TestRequire_ExternalArityIsChecked(t *testing.T) {
	src := strings.Replace(requireExternalSpec, "@external(docs_in_tenant, tenant_id, tag_ids)", "@external(docs_in_tenant, tenant_id)", 1)
	s, err := Parse(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	err = Validate(s)
	if err == nil || !strings.Contains(err.Error(), "declared with 2") {
		t.Errorf("an arity mismatch must be rejected, got: %v", err)
	}
}

func TestRequire_ExternalIsRefusedInAPermission(t *testing.T) {
	src := strings.Replace(requireExternalSpec,
		"permission create = @holds(docs:write)          @rls maps insert",
		"permission create = @holds(docs:write) + @external(docs_in_tenant, tenant_id, tag_ids) @rls maps insert", 1)
	s, err := Parse(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	err = Validate(s)
	if err == nil || !strings.Contains(err.Error(), "only in a `require` clause") {
		t.Errorf("an external predicate must never be able to confer authority, got: %v", err)
	}
}

func TestRequire_UnusedExternalIsAnError(t *testing.T) {
	src := strings.Replace(requireExternalSpec, "  require create = @external(docs_in_tenant, tenant_id, tag_ids)\n", "", 1)
	s, err := Parse(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	err = Validate(s)
	if err == nil || !strings.Contains(err.Error(), "declared but never required") {
		t.Errorf("an unused external declaration must be rejected, got: %v", err)
	}
}

func TestRequire_ExampleSpecIsTheWorkedCase(t *testing.T) {
	s, err := Parse(requireSpecSrc(t))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	res := mustEmitRLS(t, s)
	restrictive := map[string]bool{}
	for _, p := range res.Policies {
		if p.Restrictive {
			restrictive[p.Name] = true
		}
	}
	for _, want := range []string{"invitations_insert_require", "invitations_update_require"} {
		if !restrictive[want] {
			t.Errorf("examples/require.demesne must emit %s AS RESTRICTIVE, got %v", want, restrictive)
		}
	}
	if restrictive["invitations_select_require"] {
		t.Error("a require is per-verb: `require create` must not filter SELECT")
	}
}
