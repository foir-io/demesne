package demesne

import (
	"strings"
	"testing"
)

func TestEmitSupabaseProfile(t *testing.T) {
	s := mustSpec(t, runtimeSpec) // default GUC + role; contract: customer_id, project_id, sub, tenant_id
	got, err := s.EmitSupabaseProfile()
	if err != nil {
		t.Fatalf("EmitSupabaseProfile: %v", err)
	}
	mustContainAll(t, got, []string{
		"create or replace function public.demesne_access_token_hook(event jsonb)",
		"returns jsonb",
		"meta := coalesce(claims->'app_metadata', '{}'::jsonb);",
		// one lift per contract key (byte-sorted), guarded by existence:
		"if meta ? 'customer_id' then claims := jsonb_set(claims, '{customer_id}', meta->'customer_id'); end if;",
		"if meta ? 'project_id' then claims := jsonb_set(claims, '{project_id}', meta->'project_id'); end if;",
		"if meta ? 'sub' then claims := jsonb_set(claims, '{sub}', meta->'sub'); end if;",
		"if meta ? 'tenant_id' then claims := jsonb_set(claims, '{tenant_id}', meta->'tenant_id'); end if;",
		"event := jsonb_set(event, '{claims}', claims);",
		// the Supabase auth-hook grant contract:
		"grant execute on function public.demesne_access_token_hook to supabase_auth_admin;",
		"grant usage on schema public to supabase_auth_admin;",
		"revoke execute on function public.demesne_access_token_hook from authenticated, anon, public;",
		// the role-safety note:
		"service_role (BYPASSRLS)",
		`role is "authenticated"`,
	})

	// The lifts are emitted in byte-sorted contract order.
	ci := strings.Index(got, "'customer_id'")
	ti := strings.Index(got, "'tenant_id'")
	if ci < 0 || ti < 0 || ci > ti {
		t.Errorf("contract keys not emitted in sorted order (customer_id before tenant_id)")
	}
}

// A spec with a non-default claims GUC cannot use the Supabase profile (PostgREST only
// populates request.jwt.claims).
func TestEmitSupabaseProfile_RejectsCustomGUC(t *testing.T) {
	s := mustSpec(t, virtualRootSpec) // declares `claims via "app.ctx" jsonb role app_user`
	if _, err := s.EmitSupabaseProfile(); err == nil {
		t.Fatal("EmitSupabaseProfile should reject a non-request.jwt.claims setting")
	} else if !strings.Contains(err.Error(), "request.jwt.claims") {
		t.Errorf("error should explain the request.jwt.claims requirement, got: %v", err)
	}
}

func mustContainAll(t *testing.T, got string, wants []string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(got, w) {
			t.Errorf("emitted Supabase profile missing %q in:\n%s", w, got)
		}
	}
}
