package demesne

import (
	"strings"
	"testing"
)

// TestValidateRejects — each spec violates exactly one rule and must be caught.
func TestValidateRejects(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string // substring expected in the error
	}{
		{
			name: "V1 fork",
			src:  `topology { level a level b parent a level c parent a }`,
			want: "not a linear chain",
		},
		{
			name: "V1 multi-root",
			src:  `topology { level a level b }`,
			want: "exactly one root",
		},
		{
			name: "V2 bad reach",
			src: `topology { level a }
			      subject s { anchor a reach sideways identifies sub }`,
			want: "only self|descendants",
		},
		{
			name: "V2 unknown anchor",
			src: `topology { level a }
			      subject s { anchor zzz reach self identifies sub }`,
			want: "unknown level",
		},
		{
			name: "V4 publish-as-rls",
			src: `topology { level a }
			      object o { table t scoped a relation owner: c via cid
			                 permission view = owner @rls maps content:publish }`,
			want: "(V4)",
		},
		{
			name: "V6 wrong scoped order",
			src: `topology { level a level b parent a }
			      object o { table t scoped b relation r: c via cid
			                 permission p = r @rls maps select }`,
			want: "(V6)",
		},
		{
			name: "V3 unknown relation",
			src: `topology { level a }
			      object o { table t scoped a relation owner: c via cid
			                 permission view = ghost @rls maps select }`,
			want: "unknown relation",
		},
		{
			name: "V10 unknown emit-site",
			src: `topology { level a }
			      vocabulary admin { permission x:y }
			      procedures customer { a.v1.S/M -> x:y }`,
			want: "(V10)",
		},
		{
			name: "preset unknown perm",
			src: `topology { level a }
			      vocabulary v { permission a:b preset p = a:b + c:d }`,
			want: "unknown permission/preset",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := Parse(tc.src)
			if err != nil {
				// Some fixtures intentionally also lack a topology; the rule under
				// test must still be reachable. A parse error here is a fixture bug.
				t.Fatalf("fixture did not parse: %v", err)
			}
			err = Validate(spec)
			if err == nil {
				t.Fatalf("expected validation error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}
