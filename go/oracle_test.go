package demesne

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
)

type oracleCase struct {
	Kind   string          `json:"kind"`
	Input  json.RawMessage `json:"input"`
	Expect json.RawMessage `json:"expect"`
}

type oracleSpec struct {
	Projections struct {
		Claims         Claims                           `json:"claims"`
		AppSurface     []AppObjectSurface               `json:"appSurface"`
		HoldsResolver  HoldsResolver                    `json:"holdsResolver"`
		HoldsResolvers map[string]HoldsResolver         `json:"holdsResolvers"`
		RoleAssignment RoleAssignmentSurface            `json:"roleAssignment"`
		Grants         map[string]GrantSurface          `json:"grants"`
		ResourceAccess map[string]ResourceAccessSurface `json:"resourceAccess"`
	} `json:"projections"`
	Cases []oracleCase `json:"cases"`
}

type oracleInput struct {
	Local        bool              `json:"local"`
	Values       map[string]string `json:"values"`
	Extra        map[string]any    `json:"extra"`
	Object       string            `json:"object"`
	Resolver     *string           `json:"resolver"`
	Assignment   []string          `json:"assignment"`
	Query        []string          `json:"query"`
	Assignments  []RoleAssignment  `json:"assignments"`
	Scope        []string          `json:"scope"`
	AssignmentID string            `json:"assignmentID"`
	SubjectID    string            `json:"subjectID"`
	RoleID       string            `json:"roleID"`
	GrantedBy    string            `json:"grantedBy"`
	Grant        string            `json:"grant"`
	GrantID      string            `json:"grantID"`
	GranteeID    string            `json:"granteeID"`
	LevelID      string            `json:"levelID"`
	ExpiresAt    any               `json:"expiresAt"`
	ResourceID   string            `json:"resourceID"`
	Kind         string            `json:"kind"`
	PrincipalID  string            `json:"principalID"`
	Access       string            `json:"access"`
}

func stringExtra(extra map[string]any) map[string]string {
	out := map[string]string{}
	for k, v := range extra {
		out[k] = fmt.Sprint(v)
	}
	return out
}

func statement(s Statement, err error) (any, error) {
	return map[string]any{"sql": s.SQL, "args": s.Args}, err
}

func runOracleCase(ctx context.Context, r *Runtime, spec *oracleSpec, c oracleCase) (any, error) {
	var in oracleInput
	if len(c.Input) > 0 {
		if err := json.Unmarshal(c.Input, &in); err != nil {
			return nil, err
		}
	}
	p := &spec.Projections
	app := func() AppObjectSurface {
		for _, o := range p.AppSurface {
			if o.Object == in.Object {
				return o
			}
		}
		return AppObjectSurface{}
	}
	holds := func() HoldsResolver {
		if in.Resolver == nil {
			return p.HoldsResolver
		}
		return p.HoldsResolvers[*in.Resolver]
	}
	switch c.Kind {
	case "claims.claimsSetSQL":
		return p.Claims.ClaimsSetSQL(ctx, r, in.Local)
	case "claims.setRoleSQL":
		return p.Claims.SetRoleSQL(ctx, r, in.Local)
	case "claims.sessionSetupSQL":
		role, claims, err := p.Claims.SessionSetupSQL(ctx, r, in.Local)
		return []string{role, claims}, err
	case "claims.mintWithExtra":
		return r.MintClaimsValuesWithExtra(ctx, p.Claims.Contract, in.Values, stringExtra(in.Extra))
	case "appSurface.checkSQL":
		return app().CheckSQL(ctx, r)
	case "appSurface.checkManySQL":
		return app().CheckManySQL(ctx, r)
	case "appSurface.listResourcesSQL":
		return app().ListResourcesSQL(ctx, r)
	case "appSurface.checkEditSQL":
		return app().CheckEditSQL(ctx, r)
	case "appSurface.listResourcesFastSQL":
		return app().ListResourcesFastSQL(ctx, r)
	case "holds.assignmentsSQL":
		return holds().AssignmentsSQL(ctx, r)
	case "holds.scopeContains":
		return r.ScopeContains(ctx, in.Assignment, in.Query)
	case "holds.resolve":
		perms, err := holds().Resolve(ctx, r, in.Assignments, in.Scope)
		return perms.Permissions(), err
	case "roleAssignment.revokeSQL":
		return p.RoleAssignment.RevokeSQL(ctx, r)
	case "roleAssignment.listForRoleSQL":
		return p.RoleAssignment.ListForRoleSQL(ctx, r)
	case "roleAssignment.listForPrincipalSQL":
		return p.RoleAssignment.ListForPrincipalSQL(ctx, r)
	case "roleAssignment.assignInsert":
		return statement(p.RoleAssignment.AssignInsert(ctx, r, in.AssignmentID, in.SubjectID, in.RoleID, in.Scope, in.GrantedBy, in.Extra))
	case "roleAssignment.assignTouchInsert":
		return statement(p.RoleAssignment.AssignTouchInsert(ctx, r, in.AssignmentID, in.SubjectID, in.RoleID, in.Scope, in.GrantedBy, in.Extra))
	case "levelGrant.revokeSQL":
		return p.Grants[in.Grant].RevokeSQL(ctx, r)
	case "levelGrant.listSQL":
		return p.Grants[in.Grant].ListSQL(ctx, r)
	case "levelGrant.grantInsert":
		return statement(p.Grants[in.Grant].GrantInsert(ctx, r, in.GrantID, in.GranteeID, in.LevelID, in.GrantedBy, in.ExpiresAt, in.Extra))
	case "resourceAccess.modeSQL":
		return p.ResourceAccess[in.Object].ModeSQL(ctx, r)
	case "resourceAccess.setVisibilitySQL":
		return p.ResourceAccess[in.Object].SetVisibilitySQL(ctx, r)
	case "resourceAccess.listGrantsSQL":
		return p.ResourceAccess[in.Object].ListGrantsSQL(ctx, r)
	case "resourceAccess.accessorsSQL":
		return p.ResourceAccess[in.Object].AccessorsSQL(ctx, r)
	case "resourceAccess.admitsSQL":
		return p.ResourceAccess[in.Object].AdmitsSQL(ctx, r)
	case "resourceAccess.listGrantsArgs":
		return p.ResourceAccess[in.Object].ListGrantsArgs(ctx, r, "rec1")
	case "resourceAccess.grantInsert":
		return statement(p.ResourceAccess[in.Object].GrantInsert(ctx, r, in.Scope, in.ResourceID, in.Kind, in.PrincipalID, in.Access))
	case "resourceAccess.revokeDelete":
		return statement(p.ResourceAccess[in.Object].RevokeDelete(ctx, r, in.ResourceID, in.Kind, in.PrincipalID, in.Access))
	}
	return nil, fmt.Errorf("oracle: unknown case kind %q", c.Kind)
}

func normalised(v any) (any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var out any
	return out, json.Unmarshal(b, &out)
}

func TestTheRuntimeAnswersEveryOracleCaseAsTheRustRuntimeDoes(t *testing.T) {
	raw, err := os.ReadFile("../ts/packages/runtime/test/generated/oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var oracle map[string]oracleSpec
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&oracle); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	r, err := New(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(ctx)
	total := 0
	for name, spec := range oracle {
		for i, c := range spec.Cases {
			total++
			got, err := runOracleCase(ctx, r, &spec, c)
			if err != nil {
				t.Errorf("%s %s #%d: %v", name, c.Kind, i, err)
				continue
			}
			var want any
			if err := json.Unmarshal(c.Expect, &want); err != nil {
				t.Fatal(err)
			}
			if got, err = normalised(got); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("%s %s #%d:\n got %v\nwant %v", name, c.Kind, i, got, want)
			}
		}
	}
	if total <= 300 {
		t.Errorf("only %d oracle cases ran", total)
	}
}
