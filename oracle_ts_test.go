package demesne

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The cross-language differential oracle (EID-338 / WS6). This Go test writes a manifest
// — for a battery of specs, the EMITTED projections plus the EXPECTED output of every Go
// runtime builder — to ts/packages/runtime/test/generated/oracle.json. The Vitest
// oracle.test.ts loads it, feeds each projection into @demesne/runtime, and asserts the
// TS builder reproduces the Go output byte-for-byte. Nothing is hand-transcribed: the
// projection and the expectation both come from the engine, so a divergence in either
// the emit (field names) or the runtime (logic) fails the TS side.
//
// Regenerate after an intentional change:  UPDATE_ORACLE=1 go test -run TestOracle_Manifest

func oracleStmt(sql string, args []any) map[string]any {
	if args == nil {
		args = []any{}
	}
	return map[string]any{"sql": sql, "args": args}
}

func oracleCase(kind string, input map[string]any, expect any) map[string]any {
	c := map[string]any{"kind": kind, "expect": expect}
	if input != nil {
		c["input"] = input
	}
	return c
}

// canonicalScope returns n placeholder scope values ["s1".."sn"] for a parameterized write.
func canonicalScope(n int) []any {
	out := make([]any, n)
	for i := range out {
		out[i] = "s" + string(rune('1'+i))
	}
	return out
}

// canonicalExtra returns a placeholder value for each declared extra column.
func canonicalExtra(cols []string) map[string]any {
	out := map[string]any{}
	for _, c := range cols {
		out[c] = "x_" + c
	}
	return out
}

func buildOracleEntry(s *Spec) (map[string]any, error) {
	projections := map[string]any{}
	var cases []any

	// --- claims (always present) ---
	cl, err := s.tsClaimsProjection()
	if err != nil {
		return nil, err
	}
	projections["claims"] = cl
	for _, local := range []bool{true, false} {
		in := map[string]any{"local": local}
		cases = append(cases,
			oracleCase("claims.claimsSetSQL", in, s.ClaimsSetSQL(local)),
			oracleCase("claims.setRoleSQL", in, s.SetRoleSQL(local)),
			oracleCase("claims.sessionSetupSQL", in, s.SessionSetupSQL(local)),
		)
	}

	// --- app surface ---
	if surf, err := s.EmitAppSurface(); err == nil {
		objs := make([]tsAppObject, len(surf.Objects))
		for i, o := range surf.Objects {
			objs[i] = tsAppObject{o.Object, o.Table, o.PK, o.FlatListFn, o.AsyncCheckSQL, o.EditCheckSQL}
			in := map[string]any{"object": o.Object}
			cases = append(cases,
				oracleCase("appSurface.checkSQL", in, o.CheckSQL()),
				oracleCase("appSurface.checkManySQL", in, o.CheckManySQL()),
				oracleCase("appSurface.listResourcesSQL", in, o.ListResourcesSQL()),
				oracleCase("appSurface.checkEditSQL", in, o.CheckEditSQL()),
				oracleCase("appSurface.listResourcesFastSQL", in, o.ListResourcesFastSQL()),
			)
		}
		projections["appSurface"] = objs
	}

	// --- holds-resolver + role-assignment (when a rolestore exists) ---
	if len(s.RoleStores) > 0 {
		hr, err := s.HoldsResolver("")
		if err != nil {
			return nil, err
		}
		projections["holdsResolver"] = tsHolds(hr)
		cases = append(cases, oracleCase("holds.assignmentsSQL", nil, hr.AssignmentsSQL()))

		ra, err := s.RoleAssignmentSurface("")
		if err != nil {
			return nil, err
		}
		projections["roleAssignment"] = tsRoleAssign(ra)
		scope := canonicalScope(len(ra.ScopeCols))
		extra := canonicalExtra(ra.ExtraCols)
		assignIn := map[string]any{
			"assignmentID": "a1", "subjectID": "u1", "roleID": "r1",
			"scope": scope, "grantedBy": "g1", "extra": extra,
		}
		scopeStr := toStrSlice(scope)
		isql, iargs := ra.AssignInsert("a1", "u1", "r1", scopeStr, "g1", extra)
		tsql, targs := ra.AssignTouchInsert("a1", "u1", "r1", scopeStr, "g1", extra)
		cases = append(cases,
			oracleCase("roleAssignment.revokeSQL", nil, ra.RevokeSQL()),
			oracleCase("roleAssignment.listForRoleSQL", nil, ra.ListForRoleSQL()),
			oracleCase("roleAssignment.listForPrincipalSQL", nil, ra.ListForPrincipalSQL()),
			oracleCase("roleAssignment.assignInsert", assignIn, oracleStmt(isql, iargs)),
			oracleCase("roleAssignment.assignTouchInsert", assignIn, oracleStmt(tsql, targs)),
		)
	}

	// --- level grants ---
	if len(s.Grants) > 0 {
		gm := map[string]any{}
		for _, gd := range s.Grants {
			g, err := s.GrantSurface(gd.Name)
			if err != nil {
				return nil, err
			}
			gm[gd.Name] = tsGrant(g)
			extra := canonicalExtra(g.ExtraCols)
			grantIn := map[string]any{
				"grant": gd.Name, "grantID": "g1", "granteeID": "u1", "levelID": "l1",
				"grantedBy": "gb1", "expiresAt": "2030-01-01T00:00:00Z", "extra": extra,
			}
			gsql, gargs := g.GrantInsert("g1", "u1", "l1", "gb1", "2030-01-01T00:00:00Z", extra)
			cases = append(cases,
				oracleCase("levelGrant.revokeSQL", map[string]any{"grant": gd.Name}, g.RevokeSQL()),
				oracleCase("levelGrant.listSQL", map[string]any{"grant": gd.Name}, g.ListSQL()),
				oracleCase("levelGrant.grantInsert", grantIn, oracleStmt(gsql, gargs)),
			)
		}
		projections["grants"] = gm
	}

	// --- resource ACL ---
	ram := map[string]any{}
	for _, o := range s.Objects {
		if objectGrantEdge(o) == nil {
			continue
		}
		r, err := s.ResourceAccessSurface(o.Name)
		if err != nil {
			return nil, err
		}
		ram[o.Name] = tsResAccess(r)
		objIn := map[string]any{"object": o.Name}
		scope := canonicalScope(len(r.ScopeCols))
		gsql, gargs := r.GrantInsert(toStrSlice(scope), "rec1", "k1", "p1", "read")
		dsql, dargs := r.RevokeDelete("rec1", "k1", "p1", "read")
		cases = append(cases,
			oracleCase("resourceAccess.modeSQL", objIn, r.ModeSQL()),
			oracleCase("resourceAccess.setVisibilitySQL", objIn, r.SetVisibilitySQL()),
			oracleCase("resourceAccess.listGrantsSQL", objIn, r.ListGrantsSQL()),
			oracleCase("resourceAccess.accessorsSQL", objIn, r.AccessorsSQL()),
			oracleCase("resourceAccess.listGrantsArgs", objIn, r.ListGrantsArgs("rec1")),
			oracleCase("resourceAccess.grantInsert",
				map[string]any{"object": o.Name, "scope": scope, "resourceID": "rec1", "kind": "k1", "principalID": "p1", "access": "read"},
				oracleStmt(gsql, gargs)),
			oracleCase("resourceAccess.revokeDelete",
				map[string]any{"object": o.Name, "resourceID": "rec1", "kind": "k1", "principalID": "p1", "access": "read"},
				oracleStmt(dsql, dargs)),
		)
	}
	if len(ram) > 0 {
		projections["resourceAccess"] = ram
	}

	return map[string]any{"projections": projections, "cases": cases}, nil
}

func toStrSlice(xs []any) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = x.(string)
	}
	return out
}

func TestOracle_Manifest(t *testing.T) {
	specs := []struct{ name, src string }{
		{"runtime", runtimeSpec},
		{"holds", holdsSpec},
		{"fullGrant", fullGrantSpec},
		{"adminOwner", adminOwnerSpec},
		{"fullRoleStore", fullRoleStoreSpec},
		{"rpScoped", rpScopedRoleStoreSpec},
	}
	manifest := map[string]any{}
	for _, sp := range specs {
		s, err := Parse(sp.src)
		if err != nil {
			t.Fatalf("%s: parse: %v", sp.name, err)
		}
		entry, err := buildOracleEntry(s)
		if err != nil {
			t.Fatalf("%s: buildOracleEntry: %v", sp.name, err)
		}
		manifest[sp.name] = entry
	}
	got, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got = append(got, '\n')

	path := filepath.Join("ts", "packages", "runtime", "test", "generated", "oracle.json")
	if os.Getenv("UPDATE_ORACLE") != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s (%d bytes)", path, len(got))
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s missing — run: UPDATE_ORACLE=1 go test -run TestOracle_Manifest", path)
	}
	if !bytes.Equal(want, got) {
		t.Errorf("%s is out of date — run: UPDATE_ORACLE=1 go test -run TestOracle_Manifest", path)
	}
}
