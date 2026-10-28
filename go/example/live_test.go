package example

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"slices"
	"testing"

	demesne "github.com/foir-io/demesne/go"
	"github.com/foir-io/demesne/go/example/docs"
	"github.com/foir-io/demesne/go/example/notes"
	"github.com/foir-io/demesne/go/example/projection"
)

const app = "../../ts/packages/example-app/"

func TestTheGeneratedSurfaceAnswersAsLiveRLSDoes(t *testing.T) {
	db := postgres(t)
	apply(t, db, app+"sql/schema.sql", app+"generated/policies.sql")
	if _, err := db.Exec(`INSERT INTO notes (note_pk, org_ref, ws_ref, owner_ref, visibility) VALUES
		('n1', 'o1', 'w1', 'm1', 'private'),
		('n2', 'o1', 'w1', 'm2', 'open'),
		('n3', 'o1', 'w1', 'm2', 'private'),
		('n4', 'o2', 'w9', 'm1', 'private')`); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	r, err := demesne.New(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(ctx)
	s := notes.New(r)
	as := func(t *testing.T, member, org, ws string, fn func(q demesne.Querier)) {
		t.Helper()
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		minted, err := s.Mint(ctx, notes.Claims{MemberRef: member, Org: org, Ws: ws})
		if err != nil {
			t.Fatal(err)
		}
		setup := notes.SessionSetupSQL(true)
		if _, err := tx.ExecContext(ctx, setup[0]); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx, setup[1], minted); err != nil {
			t.Fatal(err)
		}
		fn(demesne.FromSQL(tx))
	}

	t.Run("CanView allows the owner and an open note, and denies another's private note and another tenant's", func(t *testing.T) {
		as(t, "m1", "o1", "w1", func(q demesne.Querier) {
			for id, want := range map[string]notes.Decision{"n1": notes.Allow, "n2": notes.Allow, "n3": notes.Deny, "n4": notes.Deny} {
				if got, err := s.Note.CanView(ctx, q, id); err != nil || got != want {
					t.Errorf("%s: got %s, %v; want %s", id, got, err, want)
				}
			}
		})
	})

	t.Run("ListResources returns exactly the rows the session reads, a page at a time", func(t *testing.T) {
		for member, want := range map[string][]string{"m1": {"n1", "n2"}, "m2": {"n2", "n3"}} {
			as(t, member, "o1", "w1", func(q demesne.Querier) {
				var got []string
				var after *string
				for {
					page, err := s.Note.ListResources(ctx, q, after, 1)
					if err != nil {
						t.Fatal(err)
					}
					if len(page) == 0 {
						break
					}
					got = append(got, page...)
					after = &page[len(page)-1]
				}
				if !reflect.DeepEqual(got, want) {
					t.Errorf("%s: got %v, want %v", member, got, want)
				}
			})
		}
	})

	t.Run("CheckMany returns the visible subset of a batch", func(t *testing.T) {
		as(t, "m1", "o1", "w1", func(q demesne.Querier) {
			got, err := s.Note.CheckMany(ctx, q, []string{"n1", "n2", "n3", "n4"})
			slices.Sort(got)
			if err != nil || !reflect.DeepEqual(got, []string{"n1", "n2"}) {
				t.Errorf("got %v, %v", got, err)
			}
		})
	})

	t.Run("Check dispatches by object and verb, and leaves an ungoverned verb ungoverned", func(t *testing.T) {
		as(t, "m1", "o1", "w1", func(q demesne.Querier) {
			for _, c := range []struct {
				object, verb, id string
				want             notes.Decision
			}{{"note", "view", "n1", notes.Allow}, {"note", "view", "n3", notes.Deny}, {"note", "delete", "n1", notes.NotGoverned}} {
				if got, err := s.Check(ctx, q, c.object, c.verb, c.id); err != nil || got != c.want {
					t.Errorf("%+v: got %s, %v", c, got, err)
				}
			}
		})
	})

	t.Run("CheckHandler answers a request with the JSON decision", func(t *testing.T) {
		as(t, "m1", "o1", "w1", func(q demesne.Querier) {
			for id, want := range map[string]string{"n1": "allow", "n3": "deny"} {
				rec := httptest.NewRecorder()
				s.CheckHandler(q).ServeHTTP(rec, httptest.NewRequest("GET", "/check?object=note&verb=view&id="+id, nil))
				var body struct{ Decision string }
				if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Decision != want || rec.Header().Get("Content-Type") != "application/json" {
					t.Errorf("%s: got %d %q %q", id, rec.Code, rec.Header().Get("Content-Type"), rec.Body.String())
				}
			}
		})
	})

	t.Run("the projections decode, and the runtime builds the same check from them", func(t *testing.T) {
		if !reflect.DeepEqual(projection.Claims.Contract, []string{"member_ref", "org", "ws"}) || len(projection.AppSurface) != 1 {
			t.Fatalf("got %+v", projection.Claims)
		}
		listed, err := projection.AppSurface[0].ListResourcesSQL(ctx, r)
		if err != nil {
			t.Fatal(err)
		}
		as(t, "m2", "o1", "w1", func(q demesne.Querier) {
			got, err := demesne.QueryIDs(ctx, q, listed, nil, 100)
			if err != nil || !reflect.DeepEqual(got, []string{"n2", "n3"}) {
				t.Errorf("got %v, %v", got, err)
			}
		})
	})
}

func TestHoldsReadsTheRolestoreAndResolvesItThroughTheRuntime(t *testing.T) {
	db := postgres(t)
	if _, err := db.Exec(`
		CREATE TABLE roles (id text PRIMARY KEY, key text NOT NULL);
		CREATE TABLE role_grants (
			grantee_kind text NOT NULL, grantee_id text NOT NULL, tenant_id text, workspace_id text,
			role_id text NOT NULL REFERENCES roles (id), revoked_at timestamptz
		);
		INSERT INTO roles VALUES ('r1', 'tenant_owner'), ('r2', 'ws_viewer');
		INSERT INTO role_grants VALUES
			('staff', 'u1', 't1', NULL, 'r1', NULL),
			('staff', 'u2', 't1', 'w1', 'r2', NULL),
			('staff', 'u2', 't1', NULL, 'r1', now()),
			('member', 'u2', 't1', NULL, 'r1', NULL)`); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	r, err := demesne.New(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(ctx)
	s := docs.New(r)
	q := demesne.FromSQL(db)
	caps := func(who string, scope ...string) docs.DocsCaps {
		t.Helper()
		held, err := s.Holds(ctx, q, who, scope)
		if err != nil {
			t.Fatal(err)
		}
		return docs.Caps(held).Docs
	}
	tiers := func(who string, scope ...string) docs.RoleSet {
		t.Helper()
		held, err := s.HoldsRoles(ctx, q, who, scope)
		if err != nil {
			t.Fatal(err)
		}
		return docs.RoleTiers(held)
	}
	for _, c := range []struct {
		who   string
		scope []string
		caps  docs.DocsCaps
		tiers docs.RoleSet
	}{
		{"u1", []string{"t1", "w1"}, docs.DocsCaps{Read: true, Write: true, Publish: true}, docs.RoleSet{TenantOwner: true}},
		{"u1", []string{"t2", "w1"}, docs.DocsCaps{}, docs.RoleSet{}},
		{"u2", []string{"t1", "w1"}, docs.DocsCaps{Read: true}, docs.RoleSet{WsViewer: true}},
		{"u2", []string{"t1", "w2"}, docs.DocsCaps{}, docs.RoleSet{}},
		{"u3", []string{"t1", "w1"}, docs.DocsCaps{}, docs.RoleSet{}},
	} {
		if got := caps(c.who, c.scope...); got != c.caps {
			t.Errorf("%s at %v: caps %+v, want %+v", c.who, c.scope, got, c.caps)
		}
		if got := tiers(c.who, c.scope...); got != c.tiers {
			t.Errorf("%s at %v: tiers %+v, want %+v", c.who, c.scope, got, c.tiers)
		}
	}
	held, err := s.Holds(ctx, q, "u1", []string{"t1", "w1"})
	if err != nil {
		t.Fatal(err)
	}
	if d := s.Doc.CanPublish(held); d != docs.Allow {
		t.Errorf("a tenant owner may not publish: %s", d)
	}
	if _, err := s.Check(ctx, q, "doc", "publish", "d1"); err == nil {
		t.Error("a capability verb answered as a row check")
	}
}
