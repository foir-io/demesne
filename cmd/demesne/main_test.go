package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const cliSpec = `
topology { level tenant level project parent tenant }
vocabulary v { permission self:read }
subject customer { anchor project reach self identifies customer_id roles configurable v binds owner }
object doc {
  table  docs
  scoped tenant > project
  relation owner: customer via customer_id
  permission view = owner @rls maps select
}
`

func writeSpec(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "s.demesne")
	if err := os.WriteFile(p, []byte(cliSpec), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCLI_PureCommands(t *testing.T) {
	spec := writeSpec(t)

	if _, err := loadSpec(spec); err != nil {
		t.Fatalf("loadSpec: %v", err)
	}
	if err := cmdValidate([]string{spec}); err != nil {
		t.Errorf("validate: %v", err)
	}
	for _, kind := range []string{"rls", "definers", "triggers", "claims", "pdp", "framework", "all"} {
		if err := cmdEmit([]string{spec, kind}); err != nil {
			t.Errorf("emit %s: %v", kind, err)
		}
	}
	if err := cmdEmit([]string{spec, "bogus"}); err == nil {
		t.Error("emit with an unknown kind should error")
	}
	if err := cmdValidate(nil); err == nil {
		t.Error("validate with no spec should error")
	}
}

func TestCLI_EmitFramework(t *testing.T) {
	spec := writeSpec(t)

	// Default package "authz".
	out := captureStdout(t, func() {
		if err := cmdEmit([]string{spec, "framework"}); err != nil {
			t.Fatalf("emit framework: %v", err)
		}
	})
	for _, want := range []string{
		"package authz",
		`demesne "github.com/eidestudio/demesne"`,
		"type Claims struct {",
		"func (docAccess) CanView(ctx context.Context, q Querier, id string) (Decision, error)",
		"func CheckHandler(q Querier) http.HandlerFunc",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("framework output missing %q", want)
		}
	}

	// A custom package name via the 3rd positional.
	out = captureStdout(t, func() {
		if err := cmdEmit([]string{spec, "framework", "access"}); err != nil {
			t.Fatalf("emit framework access: %v", err)
		}
	})
	if !strings.Contains(out, "package access") {
		t.Errorf("custom package name not honored:\n%s", out)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()
	fn()
	_ = w.Close()
	b, _ := io.ReadAll(r)
	return string(b)
}
