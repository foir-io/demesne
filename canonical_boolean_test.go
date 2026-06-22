package demesne

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCanonicalBoolean(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("examples", "canonical", "boolean.demesne"))
	if err != nil {
		t.Fatalf("read spec: %v", err)
	}

	spec, err := Parse(string(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(spec); err != nil {
		t.Fatalf("validate: %v", err)
	}

	rls, err := spec.EmitRLS()
	if err != nil {
		t.Fatalf("emit rls: %v", err)
	}

	var pred string
	for _, p := range rls.Policies {
		if p.Name == "resources_select" {
			pred = p.Using + p.Check
		}
	}
	if pred == "" {
		t.Fatalf("no resources_select policy emitted; got %d policies", len(rls.Policies))
	}

	c := "(current_setting('request.jwt.claims', true)::json ->> 'uid')"
	viewer := "viewer_id = " + c
	member := "member_id = " + c
	bannedExcluded := "(banned_id = " + c + ") IS NOT TRUE"

	if !strings.Contains(pred, "("+viewer+") AND ("+member+")") {
		t.Errorf("intersection (viewer AND member) not encoded:\n%s", pred)
	}
	if !strings.Contains(pred, member) {
		t.Errorf("member predicate missing:\n%s", pred)
	}
	if !strings.Contains(pred, bannedExcluded) {
		t.Errorf("banned exclusion not encoded as `IS NOT TRUE`:\n%s", pred)
	}
	full := "(" + viewer + ") AND (" + member + ") AND (" + bannedExcluded + ")"
	if !strings.Contains(pred, full) {
		t.Errorf("full `viewer AND member AND NOT banned` conjunction not encoded:\n%s", pred)
	}
	if strings.Contains(pred, "OR banned_id = "+c) {
		t.Errorf("banned set wrongly admitted as a positive grant:\n%s", pred)
	}
}
