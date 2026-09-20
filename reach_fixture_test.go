package demesne

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var reachFixture = readReachFixture()

func readReachFixture() string {
	src, err := os.ReadFile(filepath.Join("examples", "reach.demesne"))
	if err != nil {
		panic(err)
	}
	return string(src)
}

type reachEmission struct {
	spec     *Spec
	policies map[string]Policy
	definers map[string]GenFn
}

func emitReach(t *testing.T, src string) reachEmission {
	t.Helper()
	s, err := Parse(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	rls, err := s.EmitRLS()
	if err != nil {
		t.Fatalf("emit rls: %v", err)
	}
	if len(rls.Unsupported) > 0 {
		t.Fatalf("unsupported: %v", rls.Unsupported)
	}
	defs, err := s.EmitDefiners()
	if err != nil {
		t.Fatalf("emit definers: %v", err)
	}
	e := reachEmission{spec: s, policies: map[string]Policy{}, definers: map[string]GenFn{}}
	for _, p := range rls.Policies {
		e.policies[p.Name] = p
	}
	for _, d := range defs {
		e.definers[d.Name] = d
	}
	return e
}

func (e reachEmission) policy(t *testing.T, name string) Policy {
	t.Helper()
	p, ok := e.policies[name]
	if !ok {
		t.Fatalf("no policy %s", name)
	}
	return p
}

func (e reachEmission) definer(t *testing.T, name string) GenFn {
	t.Helper()
	d, ok := e.definers[name]
	if !ok {
		t.Fatalf("no definer %s among %v", name, keysOf(e.definers))
	}
	return d
}

func claimSQL(key string) string {
	return "(current_setting('request.jwt.claims', true)::json ->> '" + key + "')"
}

func sessionClaimSQL(key string) string {
	return "(NULLIF(current_setting('request.jwt.claims', true), '')::json ->> '" + key + "')"
}

func mustRefuse(t *testing.T, src string, want ...string) {
	t.Helper()
	s, err := Parse(src)
	if err == nil {
		err = Validate(s)
	}
	if err == nil {
		t.Fatalf("spec was accepted, want a refusal naming %q", want)
	}
	for _, w := range want {
		if !strings.Contains(err.Error(), w) {
			t.Fatalf("refusal does not name %q:\n%v", w, err)
		}
	}
}

func hasFragments(t *testing.T, what, body string, fragments ...string) {
	t.Helper()
	for _, f := range fragments {
		if !strings.Contains(body, f) {
			t.Errorf("%s lacks %q:\n%s", what, f, body)
		}
	}
}

func lacksFragments(t *testing.T, what, body string, fragments ...string) {
	t.Helper()
	for _, f := range fragments {
		if strings.Contains(body, f) {
			t.Errorf("%s carries %q:\n%s", what, f, body)
		}
	}
}
