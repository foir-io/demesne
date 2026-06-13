package demesne

import (
	"strings"
	"testing"
)

// TestDescriptorRejects checks the descriptor-specific validation rules.
func TestDescriptorRejects(t *testing.T) {
	const head = `topology { level a }
		object o { table t scoped a `
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "no owner",
			body: `descriptor { mode via m modes private grants via edge acl(r,k,p,x) }
			       permission view = @descriptor @rls maps select }`,
			want: "no owner",
		},
		{
			name: "list mode without grants",
			body: `descriptor { owner c via oid mode via m modes list "customer" }
			       permission view = @descriptor @rls maps select }`,
			want: "no `grants via edge",
		},
		{
			name: "read mode without sentinel value",
			body: `descriptor { owner c via oid mode via m modes private + read grants via edge acl(r,k,p,x) }
			       permission view = @descriptor @rls maps select }`,
			want: "expected", // parser-level: read '<sentinel>'
		},
		{
			name: "unknown mode kind",
			body: `descriptor { owner c via oid mode via m modes frobnicate }
			       permission view = @descriptor @rls maps select }`,
			want: "descriptor mode must be private",
		},
		{
			name: "column mode without mode column",
			body: `descriptor { owner c via oid modes private }
			       permission view = @descriptor @rls maps select }`,
			want: "no `mode via",
		},
		{
			name: "descriptor term without block",
			body: `relation r: c via cid
			       permission view = @descriptor @rls maps select }`,
			want: "has no descriptor block",
		},
		{
			name: "unknown builtin",
			body: `relation r: c via cid
			       permission view = @frobnicate @rls maps select }`,
			want: "unknown builtin",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := Parse(head + tc.body)
			if err != nil {
				// public-without-scope fails at parse time — that's an acceptable
				// place to catch it; check the message there.
				if strings.Contains(err.Error(), tc.want) {
					return
				}
				t.Fatalf("parse error %q did not contain %q", err.Error(), tc.want)
			}
			err = Validate(spec)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}

func hasMode(d *Descriptor, kind, value string) bool {
	for _, m := range d.Modes {
		if m.Kind == kind && m.Value == value {
			return true
		}
	}
	return false
}
