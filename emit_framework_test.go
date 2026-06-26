package demesne

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestEmitFramework_Shape(t *testing.T) {
	s := loadExample(t)
	src, err := s.EmitFramework("authz")
	if err != nil {
		t.Fatalf("EmitFramework: %v", err)
	}
	for _, want := range []string{
		"package authz",
		`demesne "github.com/foir-io/demesne"`,
		"type Decision = demesne.Decision",
		"func (c Claims) Mint() (string, error)",
		"demesne.MintClaimsValuesWithExtra(claimsContract, c.values(), c.Extra)",
		"func SessionSetupSQL(local bool) []string",
		"func (docAccess) CanView(ctx context.Context, q demesne.Querier, id string) (Decision, error)",
		"func (docAccess) ListResources(ctx context.Context, q demesne.Querier, after *string, limit int) ([]string, error)",
		"func (docAccess) CheckMany(ctx context.Context, q demesne.Querier, ids []string) ([]string, error)",
		"const AssignmentsSQL = ",
		"func ResolveHeld(assignments []demesne.RoleAssignment, scope []string) (demesne.EffectivePerms, error)",
		"func Holds(ctx context.Context, q demesne.Querier, principalID string, scope []string) (demesne.EffectivePerms, error)",
		"func Check(ctx context.Context, q demesne.Querier, object, verb, id string) (Decision, error)",
		"func CheckHandler(q demesne.Querier) http.HandlerFunc",
		"demesne.ComposeCan(true, ok, demesne.NotGoverned)",
		"func Caps(held demesne.EffectivePerms) CapSet",
		"Docs DocsCaps",
		"type DocsCaps struct {",
		"Publish: held.Holds(\"docs:publish\")",
		"func ResolveHeldRoles(assignments []demesne.RoleAssignment, scope []string) demesne.EffectiveRoles",
		"func HoldsRoles(ctx context.Context, q demesne.Querier, principalID string, scope []string) (demesne.EffectiveRoles, error)",
		"func Roles(held demesne.EffectiveRoles) RoleSet",
		"type RoleSet struct {",
		"PlatformAdmin bool",
		"PlatformAdmin: held.Holds(\"platform_admin\"),",
		"TenantOwner:   held.Holds(\"tenant_owner\"),",
		`case "doc.publish":`,
		"return NotGoverned, demesne.CapabilityGateErr(object, verb)",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("generated framework missing %q", want)
		}
	}
}

func TestEmitFramework_CompositePKSkip(t *testing.T) {
	const spec = `
topology { level tenant }
vocabulary v { permission a:read }
subject u { anchor tenant reach self identifies sub roles none }
object acl { table resource_acl pk (resource_id, principal_id, access) scoped tenant relation o: u via principal_id permission view = o @rls maps select }
object note { table notes scoped tenant relation o: u via owner_id permission view = o @rls maps select }
`
	s, err := Parse(spec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	src, err := s.EmitFramework("authz")
	if err != nil {
		t.Fatalf("EmitFramework: %v", err)
	}
	if strings.Contains(src, "aclAccess") || strings.Contains(src, `"acl.view"`) {
		t.Errorf("composite-PK object 'acl' should have NO Can surface:\n%s", src)
	}
	for _, want := range []string{
		"composite primary key",
		"acl (table resource_acl, pk resource_id, principal_id, access)",
		"func (noteAccess) CanView(",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("generated framework missing %q", want)
		}
	}
	surf, err := s.EmitAppSurface()
	if err != nil {
		t.Fatalf("EmitAppSurface: %v", err)
	}
	for _, o := range surf.Objects {
		if o.Object == "acl" {
			t.Error("EmitAppSurface should omit the composite-PK object")
		}
	}
	if _, err := s.PointCheckSQL("acl"); err == nil {
		t.Error("PointCheckSQL should error for a composite-PK object")
	}
}

func TestEmitFramework_ExampleArtifact(t *testing.T) {
	s := loadExample(t)
	src, err := s.EmitFramework("authz")
	if err != nil {
		t.Fatalf("EmitFramework: %v", err)
	}
	path := filepath.Join("examples", "authz", "authz.go")
	if os.Getenv("UPDATE_ORACLE") != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", path)
		return
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s missing — run: UPDATE_ORACLE=1 go test -run TestEmitFramework_ExampleArtifact", path)
	}
	if string(got) != src {
		t.Errorf("%s out of date — run: UPDATE_ORACLE=1 go test -run TestEmitFramework_ExampleArtifact", path)
	}
}

func TestEmitFramework_SupabaseArtifact(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("examples", "supabase.demesne"))
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
	gen, err := s.EmitFramework("supabaseauthz")
	if err != nil {
		t.Fatalf("EmitFramework: %v", err)
	}
	path := filepath.Join("examples", "supabaseauthz", "authz.go")
	if os.Getenv("UPDATE_ORACLE") != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(gen), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", path)
		return
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s missing — run: UPDATE_ORACLE=1 go test -run TestEmitFramework_SupabaseArtifact", path)
	}
	if string(got) != gen {
		t.Errorf("%s out of date — run: UPDATE_ORACLE=1 go test -run TestEmitFramework_SupabaseArtifact", path)
	}
}

func TestEmitFramework_Compiles(t *testing.T) {
	if testing.Short() {
		t.Skip("-short: skipping the go-build compile proof")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain unavailable")
	}
	s := loadExample(t)
	src, err := s.EmitFramework("authz")
	if err != nil {
		t.Fatalf("EmitFramework: %v", err)
	}
	repo, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "authz"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "authz", "authz.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	gomod := "module fwtest\n\ngo 1.26.1\n\nrequire github.com/foir-io/demesne v0.0.0\n\nreplace github.com/foir-io/demesne => " + repo + "\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "build", "./...")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOPROXY=off", "GOFLAGS=-mod=mod", "GOWORK=off")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generated framework does not compile:\n%s\n--- generated ---\n%s", out, src)
	}
}
