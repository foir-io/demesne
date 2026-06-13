package demesne

import (
	"testing"
)

func TestEmitPDP_Rejects(t *testing.T) {
	cases := map[string]string{
		"perm not in vocab": `vocabulary admin { permission content:read }
			procedures admin { a.v1.S/M -> content:write }`,
		"governed and ungoverned": `vocabulary admin { permission content:read }
			procedures admin { a.v1.S/M -> content:read }
			ungoverned admin { a.v1.S/M : "nope" }`,
		"unknown emit-site": `vocabulary admin { permission content:read }
			procedures customer { a.v1.S/M -> content:read }`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			spec, err := Parse(src)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if _, err := spec.EmitPDP(); err == nil {
				t.Fatalf("expected PDP emit error for %q", name)
			}
		})
	}
}
