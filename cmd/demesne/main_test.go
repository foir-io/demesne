package main

import (
	"os"
	"path/filepath"
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
