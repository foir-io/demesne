package demesne

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

type oracleCase struct {
	Kind   string          `json:"kind"`
	Input  json.RawMessage `json:"input"`
	Expect json.RawMessage `json:"expect"`
}

type oracleSpec struct {
	Projections struct {
		Claims struct {
			Contract []string `json:"contract"`
		} `json:"claims"`
		HoldsResolver  *HoldsResolver            `json:"holdsResolver"`
		HoldsResolvers map[string]*HoldsResolver `json:"holdsResolvers"`
	} `json:"projections"`
	Cases []oracleCase `json:"cases"`
}

func TestOracle_RuntimeMatchesTheCompiler(t *testing.T) {
	src, err := os.ReadFile("../ts/packages/runtime/test/generated/oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var oracle map[string]oracleSpec
	if err := json.Unmarshal(src, &oracle); err != nil {
		t.Fatal(err)
	}
	replayed := 0
	for name, spec := range oracle {
		for i, c := range spec.Cases {
			var in struct {
				Resolver    *string           `json:"resolver"`
				Assignments []RoleAssignment  `json:"assignments"`
				Scope       []string          `json:"scope"`
				Assignment  []string          `json:"assignment"`
				Query       []string          `json:"query"`
				Values      map[string]string `json:"values"`
				Extra       map[string]string `json:"extra"`
			}
			if len(c.Input) > 0 {
				if err := json.Unmarshal(c.Input, &in); err != nil {
					t.Fatalf("%s #%d: %v", name, i, err)
				}
			}
			resolver := spec.Projections.HoldsResolver
			if in.Resolver != nil {
				resolver = spec.Projections.HoldsResolvers[*in.Resolver]
			}
			var got any
			switch c.Kind {
			case "holds.resolve":
				held, err := resolver.Resolve(in.Assignments, in.Scope)
				if err != nil {
					t.Fatalf("%s #%d: %v", name, i, err)
				}
				got = held.Permissions()
			case "holds.scopeContains":
				got = scopeContains(in.Assignment, in.Query)
			case "holds.assignmentsSQL":
				got = resolver.AssignmentsSQL()
			case "claims.mintWithExtra":
				minted, err := MintClaimsValuesWithExtra(spec.Projections.Claims.Contract, in.Values, in.Extra)
				if err != nil {
					t.Fatalf("%s #%d: %v", name, i, err)
				}
				got = minted
			default:
				continue
			}
			want := reflect.New(reflect.TypeOf(got)).Interface()
			if err := json.Unmarshal(c.Expect, want); err != nil {
				t.Fatalf("%s #%d %s: %v", name, i, c.Kind, err)
			}
			if !reflect.DeepEqual(got, reflect.ValueOf(want).Elem().Interface()) {
				t.Errorf("%s #%d %s: got %#v, want %s", name, i, c.Kind, got, c.Expect)
			}
			replayed++
		}
	}
	if replayed != 392 {
		t.Fatalf("replayed %d oracle cases, want 392", replayed)
	}
}
