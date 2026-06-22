package demesne

import (
	"strings"
	"testing"
)

func TestEnablementSQL(t *testing.T) {
	s := mustSpec(t, `
		topology { level tenant level project parent tenant }
		vocabulary v { permission self:read }
		subject customer { anchor project reach self identifies customer_id roles configurable v binds owner }
		object record  { table records scoped tenant > project relation owner: customer via customer_id permission view = owner @rls maps select }
		object file    { table files   scoped tenant > project relation owner: customer via customer_id permission view = owner @rls maps select }`)
	res, err := s.EmitRLS()
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	if got := res.GovernedTables(); strings.Join(got, ",") != "files,records" {
		t.Errorf("governed tables = %v, want [files records]", got)
	}
	sql := res.EnablementSQL()
	for _, want := range []string{
		"ALTER TABLE public.files ENABLE ROW LEVEL SECURITY;",
		"ALTER TABLE public.files FORCE ROW LEVEL SECURITY;",
		"ALTER TABLE public.records ENABLE ROW LEVEL SECURITY;",
		"ALTER TABLE public.records FORCE ROW LEVEL SECURITY;",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("enablement SQL missing %q:\n%s", want, sql)
		}
	}

	if strings.Index(sql, "public.files") > strings.Index(sql, "public.records") {
		t.Errorf("enablement SQL not sorted by table:\n%s", sql)
	}
}
