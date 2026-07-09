package demesne

import (
	"go/format"
	"strings"
	"testing"
)

const fieldAccessSpec = `
topology { level tenant level project parent tenant }
object record {
  table records
  scoped tenant > project
  fields { self service scoped admin public }
  field ssn { read = admin write = admin }
  field nickname { read = public + self write = self + admin }
  field secret { write = admin column secret_col }
}
`

func TestEmitFieldAccess(t *testing.T) {
	spec, err := Parse(fieldAccessSpec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	out, err := spec.EmitFieldAccess()
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	fa := out["record"]
	if fa == nil {
		t.Fatalf("no field-access for object record, got %v", out)
	}
	if got, want := len(fa.Principals), 5; got != want {
		t.Errorf("principals = %d, want %d (%v)", got, want, fa.Principals)
	}
	if fa.Principals[0] != "admin" {
		t.Errorf("principals not sorted: %v", fa.Principals)
	}
	if len(fa.Rules) != 3 {
		t.Fatalf("rules = %d, want 3", len(fa.Rules))
	}

	goSrc := fa.RenderGo()
	if _, err := format.Source([]byte("package p\n" + goSrc)); err != nil {
		t.Fatalf("rendered Go does not compile: %v\n%s", err, goSrc)
	}
	for _, want := range []string{
		"type RecordFieldPrincipal string",
		"RecordFieldAdmin RecordFieldPrincipal = \"admin\"",
		"type RecordFieldPolicy struct",
		"func NewRecordFieldPolicy()",
		"p.write[\"ssn\"] = []RecordFieldPrincipal{RecordFieldAdmin}",
		"p.read[\"nickname\"] = []RecordFieldPrincipal{RecordFieldPublic, RecordFieldSelf}",
		"func (p *RecordFieldPolicy) CanReadField(field string, who RecordFieldPrincipal) bool",
		"func (p *RecordFieldPolicy) CanWriteField(field string, who RecordFieldPrincipal) bool",
		"func (p *RecordFieldPolicy) SetWrite(field string, who ...RecordFieldPrincipal)",
	} {
		if !strings.Contains(goSrc, want) {
			t.Errorf("rendered Go missing %q\n---\n%s", want, goSrc)
		}
	}

	tsSrc := fa.RenderTS()
	for _, want := range []string{
		`export type RecordFieldPrincipal = "admin" | "public" | "scoped" | "self" | "service";`,
		"export class RecordFieldPolicy {",
		`this.write.set("ssn", ["admin"]);`,
		`this.read.set("nickname", ["public", "self"]);`,
		"canWriteField(field: string, who: RecordFieldPrincipal): boolean",
	} {
		if !strings.Contains(tsSrc, want) {
			t.Errorf("rendered TS missing %q\n---\n%s", want, tsSrc)
		}
	}

	grants := fa.RenderGrants("records")
	if !strings.Contains(grants, "GRANT UPDATE (secret_col) ON records TO admin;") {
		t.Errorf("grants missing the secret_col floor path:\n%s", grants)
	}
	if strings.Contains(grants, "ssn") {
		t.Errorf("ssn has no column, must not appear in grants:\n%s", grants)
	}
}

func TestFieldAccess_ValidateRejects(t *testing.T) {
	const hdr = "topology { level tenant level project parent tenant }\n"
	cases := map[string]string{
		"field rule without principals": hdr + `object record {
			table records
			scoped tenant > project
			field ssn { write = admin }
		}`,
		"token not a declared principal": hdr + `object record {
			table records
			scoped tenant > project
			fields { self admin }
			field ssn { write = superuser }
		}`,
		"duplicate field": hdr + `object record {
			table records
			scoped tenant > project
			fields { self admin }
			field ssn { write = admin }
			field ssn { write = self }
		}`,
		"duplicate principal": hdr + `object record {
			table records
			scoped tenant > project
			fields { admin admin }
			field ssn { write = admin }
		}`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			spec, err := Parse(src)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			err = Validate(spec)
			if err == nil {
				t.Fatalf("expected a validation error for %q", name)
			}
			if !strings.Contains(err.Error(), "field") {
				t.Errorf("error does not mention the field-access problem: %v", err)
			}
		})
	}
}
