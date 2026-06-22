package main

import (
	"io"
	"os"
	"path/filepath"
	"reflect"
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
	for _, kind := range []string{"rls", "definers", "triggers", "claims", "pdp", "all"} {
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

func TestStripTargetFlag(t *testing.T) {
	cases := []struct {
		in     []string
		target string
		rest   []string
	}{
		{[]string{"s.demesne"}, "go", []string{"s.demesne"}},
		{[]string{"s.demesne", "--target", "ts"}, "ts", []string{"s.demesne"}},
		{[]string{"--target=ts", "s.demesne", "all"}, "ts", []string{"s.demesne", "all"}},
		{[]string{"s.demesne", "claims", "--target", "ts"}, "ts", []string{"s.demesne", "claims"}},
	}
	for _, c := range cases {
		gotT, gotR := stripTargetFlag(c.in)
		if gotT != c.target || !reflect.DeepEqual(gotR, c.rest) {
			t.Errorf("stripTargetFlag(%v) = %q,%v; want %q,%v", c.in, gotT, gotR, c.target, c.rest)
		}
	}
}

func TestCLI_EmitTS(t *testing.T) {
	spec := writeSpec(t)

	for _, kind := range []string{"claims", "pdp", "projections", "all"} {
		if err := cmdEmit([]string{spec, kind, "--target", "ts"}); err != nil {
			t.Errorf("emit %s --target ts: %v", kind, err)
		}
	}
	// The language-neutral SQL/DDL kinds have no TS target.
	for _, kind := range []string{"rls", "definers", "enablement", "triggers"} {
		if err := cmdEmit([]string{spec, kind, "--target", "ts"}); err == nil {
			t.Errorf("emit %s --target ts should error (language-neutral)", kind)
		}
	}
	if err := cmdEmit([]string{spec, "--target", "rust"}); err == nil {
		t.Error("an unknown --target should error")
	}

	// The =form works and the flag is order-independent; the output is a TS module.
	out := captureStdout(t, func() {
		if err := cmdEmit([]string{spec, "--target=ts", "projections"}); err != nil {
			t.Fatalf("emit projections --target=ts: %v", err)
		}
	})
	if !strings.Contains(out, `from "@demesne/runtime"`) || !strings.Contains(out, "export const claims: Claims") {
		t.Errorf("projections output is not the expected TypeScript module:\n%s", out)
	}
}

func TestCLI_EmitProfileSupabase(t *testing.T) {
	spec := writeSpec(t)
	out := captureStdout(t, func() {
		if err := cmdEmit([]string{spec, "--profile", "supabase"}); err != nil {
			t.Fatalf("emit --profile supabase: %v", err)
		}
	})
	for _, want := range []string{
		"create or replace function public.demesne_access_token_hook(event jsonb)",
		"grant execute on function public.demesne_access_token_hook to supabase_auth_admin;",
		"if meta ? 'customer_id'",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("supabase profile output missing %q:\n%s", want, out)
		}
	}
	if err := cmdEmit([]string{spec, "--profile", "firebase"}); err == nil {
		t.Error("an unknown --profile should error")
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
