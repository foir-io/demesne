package demesne

import (
	"strings"
	"testing"
)

const viaObjectSpec = `
topology { level tenant level project parent tenant }
vocabulary v { permission self:read }
subject customer { anchor project reach self identifies cust roles configurable v binds owner }
object document {
  table  documents
  scoped tenant > project
  relation owner: customer via owner_id
  permission view = owner @rls maps select
}
object comment {
  table  comments
  scoped tenant > project
  relation doc: document via object document->view on document_id
  permission view = doc @rls maps select
}
`

func TestViaObject_CrossObjectReference(t *testing.T) {
	s, err := Parse(viaObjectSpec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}

	rls, err := s.EmitRLS()
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	cs := findPolicy(rls, "comments_select")
	if cs == nil {
		t.Fatalf("no comments_select (unsupported: %v)", rls.Unsupported)
	}

	if !strings.Contains(cs.Using, "auth.document_can_view(document_id)") {
		t.Errorf("comments_select missing the cross-object reference:\n%s", cs.Using)
	}

	defs, err := s.EmitDefiners()
	if err != nil {
		t.Fatalf("definers: %v", err)
	}
	var can *GenFn
	for i := range defs {
		if defs[i].Name == "document_can_view" {
			can = &defs[i]
		}
	}
	if can == nil {
		t.Fatal("no document_can_view definer (V11 would dangle)")
	}
	c := "(current_setting('request.jwt.claims', true)::json ->> 'cust')"

	if !strings.HasPrefix(can.Body, "EXISTS (SELECT 1 FROM documents WHERE documents.id = p_document_id AND (") {
		t.Errorf("definer does not wrap the document predicate at the related row:\n%s", can.Body)
	}
	if !strings.Contains(can.Body, "owner_id = "+c) {
		t.Errorf("definer does not embed the document's own grant predicate:\n%s", can.Body)
	}
}

func TestViaObject_CycleRejected(t *testing.T) {
	s := mustSpec(t, `
		topology { level tenant level project parent tenant }
		object a { table at scoped tenant > project relation r: b via object b->view on b_id permission view = r @rls maps select }
		object b { table bt scoped tenant > project relation r: a via object a->view on a_id permission view = r @rls maps select }`)
	if err := Validate(s); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Errorf("mutually-referencing objects should be rejected as a cycle, got: %v", err)
	}
}

func TestViaObject_UnknownObjectRejected(t *testing.T) {
	s := mustSpec(t, `
		topology { level tenant level project parent tenant }
		object comment { table comments scoped tenant > project relation doc: nope via object nope->view on doc_id permission view = doc @rls maps select }`)
	if err := Validate(s); err == nil || !strings.Contains(err.Error(), "unknown object") {
		t.Errorf("reference to an unknown object should be rejected, got: %v", err)
	}
}
