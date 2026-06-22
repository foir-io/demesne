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
		`demesne "github.com/eidestudio/demesne"`,
		"type Decision = demesne.Decision",
		"type Querier interface {",
		"func FromSQL(db sqlDB) Querier",
		"type Claims struct {",
		"func (c Claims) Mint() (string, error)",
		"func SessionSetupSQL(local bool) []string",
		"func (docAccess) CanView(ctx context.Context, q Querier, id string) (Decision, error)",
		"func (docAccess) ListResources(ctx context.Context, q Querier, after *string, limit int) ([]string, error)",
		"func (docAccess) CheckMany(ctx context.Context, q Querier, ids []string) ([]string, error)",
		"func Holds(ctx context.Context, q Querier, principalID string, scope []string) (demesne.EffectivePerms, error)",
		"func CheckHandler(q Querier) http.HandlerFunc",
		"demesne.ComposeCan(true, ok, demesne.NotGoverned)",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("generated framework missing %q", want)
		}
	}
}

// The committed worked-example package (examples/authz/authz.go) is generated from
// example.demesne and built by `go build ./...` — an always-on compile proof + a readable
// reference. This golden test keeps it in lockstep with the emitter.
//
// Regenerate:  UPDATE_ORACLE=1 go test -run TestEmitFramework_ExampleArtifact
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

// The Supabase worked example's framework package (examples/supabaseauthz/authz.go),
// generated from supabase.demesne and imported by the Go round-trip in cmd/demesne. Built
// by `go build ./...`; this golden keeps it in sync.
//
// Regenerate:  UPDATE_ORACLE=1 go test -run TestEmitFramework_SupabaseArtifact
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

// The generated package must COMPILE against the engine — the real proof it is valid Go.
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
	gomod := "module fwtest\n\ngo 1.26.1\n\nrequire github.com/eidestudio/demesne v0.0.0\n\nreplace github.com/eidestudio/demesne => " + repo + "\n"
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
