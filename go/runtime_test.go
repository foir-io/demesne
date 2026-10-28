package demesne

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func runtime(t *testing.T) (context.Context, *Runtime) {
	t.Helper()
	ctx := context.Background()
	r, err := New(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	return ctx, r
}

var pdp = PDP{
	EmitSite:   "api",
	Policy:     map[string]string{"/docs.v1.DocService/GetDoc": "docs:read"},
	Ungoverned: map[string]string{"/health.v1.Health/Check": "public probe"},
}

func TestAuthorizeAsksHoldsOnlyForAGovernedProcedure(t *testing.T) {
	ctx, r := runtime(t)
	for _, tc := range []struct {
		procedure string
		held      bool
		want      Decision
		asked     []string
	}{
		{"/docs.v1.DocService/GetDoc", true, Allow, []string{"docs:read"}},
		{"/docs.v1.DocService/GetDoc", false, Deny, []string{"docs:read"}},
		{"/health.v1.Health/Check", true, NotGoverned, nil},
	} {
		var asked []string
		got, err := r.Authorize(ctx, pdp, tc.procedure, func(perm string) bool {
			asked = append(asked, perm)
			return tc.held
		})
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.want || strings.Join(asked, ",") != strings.Join(tc.asked, ",") {
			t.Errorf("%s held=%v: got %s asking %v, want %s asking %v", tc.procedure, tc.held, got, asked, tc.want, tc.asked)
		}
	}
}

func TestCallsFromManyGoroutinesEachGetTheirOwnAnswer(t *testing.T) {
	ctx, r := runtime(t)
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for g := range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			want := map[bool]Decision{true: Allow, false: Deny}[g%2 == 0]
			for range 50 {
				got, err := r.Authorize(ctx, pdp, "/docs.v1.DocService/GetDoc", func(string) bool { return g%2 == 0 })
				if err != nil || got != want {
					errs <- errors.Join(err, errors.New("goroutine got another goroutine's answer"))
					return
				}
				in, err := r.ScopeContains(ctx, []string{"t1"}, []string{"t1", "w1"})
				if err != nil || !in {
					errs <- errors.Join(err, errors.New("scope containment answered wrongly under load"))
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

func TestARefusalIsTheRuntimesOwnMessage(t *testing.T) {
	ctx, r := runtime(t)
	_, err := r.WithinPlane(ctx, []string{"t1"}, -1)
	var refused *Error
	if !errors.As(err, &refused) || refused.Message != "demesne runtime: holds.withinPlane: depth must be a non-negative integer" {
		t.Fatalf("got %v", err)
	}
	err = r.Call(ctx, "nope", map[string]any{}, new(any))
	if !errors.As(err, &refused) || refused.Message != `demesne runtime: no operation "nope"` {
		t.Fatalf("got %v", err)
	}
	if _, err := r.ScopeContains(ctx, []string{"t1"}, []string{"t1"}); err != nil {
		t.Fatalf("a refusal leaves the runtime usable: %v", err)
	}
}

func TestANilListIsAnEmptyOne(t *testing.T) {
	ctx, r := runtime(t)
	in, err := r.ScopeContains(ctx, nil, nil)
	if err != nil || !in {
		t.Fatalf("got %v, %v", in, err)
	}
}

func TestADriverValueComesBackAsTheSameValue(t *testing.T) {
	ctx, r := runtime(t)
	g := GrantSurface{
		Name: "support", Level: "tenant", Table: "support_grants", GranteeCol: "grantee_id", LevelCol: "tenant_id",
		ActiveCol: "revoked_at", ExpiresCol: "expires_at", PK: "id", GrantedByCol: "granted_by", CreatedAtCol: "created_at",
		ExtraCols: []string{"reason"},
	}
	expires := time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)
	s, err := g.GrantInsert(ctx, r, "g1", "u1", "t1", "admin", expires, map[string]any{"reason": 42})
	if err != nil {
		t.Fatal(err)
	}
	var sawTime, sawReason bool
	for _, a := range s.Args {
		sawTime = sawTime || a == any(expires)
		sawReason = sawReason || a == any(42)
	}
	if !sawTime || !sawReason || !strings.Contains(s.SQL, "INSERT INTO support_grants") {
		t.Fatalf("got %+v", s)
	}
	none, err := g.GrantInsert(ctx, r, "g2", "u1", "t1", "admin", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range none.Args {
		if a == any(expires) {
			t.Fatalf("a value from another call leaked in: %+v", none)
		}
	}
}
