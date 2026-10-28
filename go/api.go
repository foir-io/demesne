package demesne

import (
	"context"
	"strconv"
	"strings"
)

func list(xs []string) []string {
	if xs == nil {
		return []string{}
	}
	return xs
}

func dict(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

func get[T any](ctx context.Context, r *Runtime, op string, args map[string]any) (T, error) {
	var out T
	err := r.Call(ctx, op, args, &out)
	return out, err
}

const mark = "\x00demesne:"

type driverValues struct {
	values []any
}

func (d *driverValues) hold(v any) *string {
	if v == nil {
		return nil
	}
	d.values = append(d.values, v)
	s := mark + strconv.Itoa(len(d.values)-1)
	return &s
}

func (d *driverValues) holdAll(extra map[string]any) map[string]string {
	out := map[string]string{}
	for k, v := range extra {
		if held := d.hold(v); held != nil {
			out[k] = *held
		}
	}
	return out
}

func (d *driverValues) statement(ctx context.Context, r *Runtime, op string, args map[string]any) (Statement, error) {
	raw, err := get[struct {
		SQL  string    `json:"sql"`
		Args []*string `json:"args"`
	}](ctx, r, op, args)
	if err != nil {
		return Statement{}, err
	}
	out := Statement{SQL: raw.SQL, Args: make([]any, len(raw.Args))}
	for i, a := range raw.Args {
		switch {
		case a == nil:
			out.Args[i] = nil
		case strings.HasPrefix(*a, mark):
			n, err := strconv.Atoi(strings.TrimPrefix(*a, mark))
			if err != nil || n < 0 || n >= len(d.values) {
				return Statement{}, &Error{Message: "demesne runtime: " + op + ": an argument names no value the caller supplied"}
			}
			out.Args[i] = d.values[n]
		default:
			out.Args[i] = *a
		}
	}
	return out, nil
}

// ClaimsContract returns the keys of a claims contract, in order.
func ClaimsContract(entries []ClaimEntry) []string {
	keys := make([]string, len(entries))
	for i, e := range entries {
		keys[i] = e.Key
	}
	return keys
}

// Mint returns the claims JSON for values, refusing a key outside the contract.
func (c Claims) Mint(ctx context.Context, r *Runtime, values map[string]string) (string, error) {
	return get[string](ctx, r, "claims.mint", map[string]any{"claims": c, "values": dict(values)})
}

// Build returns the claim values for p: its identity under its subject's claim, and its scope at each level.
func (c Claims) Build(ctx context.Context, r *Runtime, p Principal) (map[string]string, error) {
	p.Scopes = dict(p.Scopes)
	return get[map[string]string](ctx, r, "claims.build", map[string]any{"claims": c, "principal": p})
}

// MintFor returns the claims JSON for p.
func (c Claims) MintFor(ctx context.Context, r *Runtime, p Principal) (string, error) {
	p.Scopes = dict(p.Scopes)
	return get[string](ctx, r, "claims.mintFor", map[string]any{"claims": c, "principal": p})
}

// SetRoleSQL returns the statement that switches to the session role, for the transaction when local, else for the
// session.
func (c Claims) SetRoleSQL(ctx context.Context, r *Runtime, local bool) (string, error) {
	return get[string](ctx, r, "claims.setRoleSQL", map[string]any{"claims": c, "local": local})
}

// ClaimsSetSQL returns the statement that sets the claims setting to its one argument, for the transaction when local,
// else for the session.
func (c Claims) ClaimsSetSQL(ctx context.Context, r *Runtime, local bool) (string, error) {
	return get[string](ctx, r, "claims.claimsSetSQL", map[string]any{"claims": c, "local": local})
}

// SessionSetupSQL returns the two statements that set up a session: the role, then the claims.
func (c Claims) SessionSetupSQL(ctx context.Context, r *Runtime, local bool) (setRole, setClaims string, err error) {
	both, err := get[[]string](ctx, r, "claims.sessionSetupSQL", map[string]any{"claims": c, "local": local})
	if err != nil {
		return "", "", err
	}
	if len(both) != 2 {
		return "", "", &Error{Message: "demesne runtime: claims.sessionSetupSQL: want two statements"}
	}
	return both[0], both[1], nil
}

// MintClaimsValuesWithExtra returns the claims JSON for values under contract, with extra claims beside it.
func (r *Runtime) MintClaimsValuesWithExtra(ctx context.Context, contract []string, values, extra map[string]string) (string, error) {
	return get[string](ctx, r, "claims.mintWithExtra", map[string]any{"contract": list(contract), "values": dict(values), "extra": dict(extra)})
}

// ComposeCan combines a row's point check with the policy decision point's decision for the same call: either one
// denying denies, neither governing leaves it ungoverned, and anything else allows.
func (r *Runtime) ComposeCan(ctx context.Context, pointGoverned, pointAllow bool, pdp Decision) (Decision, error) {
	return get[Decision](ctx, r, "pdp.composeCan", map[string]any{"pointGoverned": pointGoverned, "pointAllow": pointAllow, "pdp": pdp})
}

// CheckSQL returns the object's read check for one row.
func (o AppObjectSurface) CheckSQL(ctx context.Context, r *Runtime) (string, error) {
	return get[string](ctx, r, "app.checkSQL", map[string]any{"object": o})
}

// CheckManySQL returns the object's read check over a list of rows.
func (o AppObjectSurface) CheckManySQL(ctx context.Context, r *Runtime) (string, error) {
	return get[string](ctx, r, "app.checkManySQL", map[string]any{"object": o})
}

// ListResourcesSQL returns the object's paged listing of the rows a caller reads.
func (o AppObjectSurface) ListResourcesSQL(ctx context.Context, r *Runtime) (string, error) {
	return get[string](ctx, r, "app.listResourcesSQL", map[string]any{"object": o})
}

// CheckEditSQL returns the object's edit check for one row.
func (o AppObjectSurface) CheckEditSQL(ctx context.Context, r *Runtime) (string, error) {
	return get[string](ctx, r, "app.checkEditSQL", map[string]any{"object": o})
}

// ListResourcesFastSQL returns the object's listing through its flattened membership, where it has one.
func (o AppObjectSurface) ListResourcesFastSQL(ctx context.Context, r *Runtime) (string, error) {
	return get[string](ctx, r, "app.listResourcesFastSQL", map[string]any{"object": o})
}

// ImpliedPermissions returns perm and every permission it implies.
func (v Vocabulary) ImpliedPermissions(ctx context.Context, r *Runtime, perm string) ([]string, error) {
	return get[[]string](ctx, r, "vocab.impliedPermissions", map[string]any{"vocab": v, "perm": perm})
}

// ExpandImplications returns perms with everything they imply.
func (v Vocabulary) ExpandImplications(ctx context.Context, r *Runtime, perms []string) ([]string, error) {
	return get[[]string](ctx, r, "vocab.expandImplications", map[string]any{"vocab": v, "perms": list(perms)})
}

// PresetPermissions returns the permissions the preset named name grants.
func (v Vocabulary) PresetPermissions(ctx context.Context, r *Runtime, name string) ([]string, error) {
	return get[[]string](ctx, r, "vocab.presetPermissions", map[string]any{"vocab": v, "name": name})
}

// RankOf returns the preset's place in the vocabulary's ranking, and whether it is ranked.
func (v Vocabulary) RankOf(ctx context.Context, r *Runtime, preset string) (index int, ok bool, err error) {
	got, err := get[struct {
		Index int  `json:"index"`
		OK    bool `json:"ok"`
	}](ctx, r, "vocab.rankOf", map[string]any{"vocab": v, "preset": preset})
	return got.Index, got.OK, err
}

// PresetsAtOrAbove returns the presets ranked at or above threshold.
func (v Vocabulary) PresetsAtOrAbove(ctx context.Context, r *Runtime, threshold string) ([]string, error) {
	return get[[]string](ctx, r, "vocab.presetsAtOrAbove", map[string]any{"vocab": v, "threshold": threshold})
}

// CapGrant reports whether a holder of held may grant requested.
func (v Vocabulary) CapGrant(ctx context.Context, r *Runtime, held, requested []string) (DelegationCap, error) {
	return get[DelegationCap](ctx, r, "vocab.capGrant", map[string]any{"vocab": v, "held": list(held), "requested": list(requested)})
}

// Depth returns how many scope levels the rolestore's plane covers.
func (h HoldsResolver) Depth(ctx context.Context, r *Runtime) (int, error) {
	return get[int](ctx, r, "holds.planeDepth", map[string]any{"resolver": h})
}

// SelectedScopeCols returns the scope columns the assignments query reads.
func (h HoldsResolver) SelectedScopeCols(ctx context.Context, r *Runtime) ([]string, error) {
	return get[[]string](ctx, r, "holds.selectedScopeCols", map[string]any{"resolver": h})
}

// AssignmentsSQL returns the query that reads a subject's active role assignments.
func (h HoldsResolver) AssignmentsSQL(ctx context.Context, r *Runtime) (string, error) {
	return get[string](ctx, r, "holds.assignmentsSQL", map[string]any{"resolver": h})
}

// Resolve returns the permissions assignments grant at scope.
func (h HoldsResolver) Resolve(ctx context.Context, r *Runtime, assignments []RoleAssignment, scope []string) (EffectivePerms, error) {
	perms, err := get[[]string](ctx, r, "holds.resolve", map[string]any{"resolver": h, "assignments": roleAssignments(assignments), "scope": list(scope)})
	return EffectivePerms{perms: perms, held: setOf(perms)}, err
}

func roleAssignments(as []RoleAssignment) []RoleAssignment {
	out := make([]RoleAssignment, len(as))
	for i, a := range as {
		out[i] = RoleAssignment{Scope: list(a.Scope), RoleKey: a.RoleKey, Permissions: list(a.Permissions)}
	}
	return out
}

// ScopeContains reports whether an assignment made at assignment covers query.
func (r *Runtime) ScopeContains(ctx context.Context, assignment, query []string) (bool, error) {
	return get[bool](ctx, r, "holds.scopeContains", map[string]any{"assignment": list(assignment), "query": list(query)})
}

// WithinPlane reports whether scope lies within a plane depth levels deep.
func (r *Runtime) WithinPlane(ctx context.Context, scope []string, depth int) (bool, error) {
	return get[bool](ctx, r, "holds.withinPlane", map[string]any{"scope": list(scope), "depth": depth})
}

// NewEffectiveRoles returns the roles keyed keys.
func (r *Runtime) NewEffectiveRoles(ctx context.Context, keys []string) (EffectiveRoles, error) {
	roles, err := get[[]string](ctx, r, "roles.new", map[string]any{"keys": list(keys)})
	return EffectiveRoles{roles: roles, held: setOf(roles)}, err
}

// ResolveRoles returns the roles assignments hold at scope.
func (r *Runtime) ResolveRoles(ctx context.Context, assignments []RoleAssignment, scope []string) (EffectiveRoles, error) {
	roles, err := get[[]string](ctx, r, "roles.resolve", map[string]any{"assignments": roleAssignments(assignments), "scope": list(scope)})
	return EffectiveRoles{roles: roles, held: setOf(roles)}, err
}

// TouchOnConflict returns the ON CONFLICT clause that refreshes an edge keyed by bareKey and nullableKey, setting sets.
func (r *Runtime) TouchOnConflict(ctx context.Context, bareKey, nullableKey, sets []string) (string, error) {
	return get[string](ctx, r, "grants.touchOnConflict", map[string]any{"bareKey": list(bareKey), "nullableKey": list(nullableKey), "sets": list(sets)})
}

func (p RoleAssignmentSurface) assign(ctx context.Context, r *Runtime, op, assignmentID, subjectID, roleID string, scope []string, grantedBy string, extra map[string]any) (Statement, error) {
	values := &driverValues{}
	return values.statement(ctx, r, op, map[string]any{
		"surface": p, "assignmentID": assignmentID, "subjectID": subjectID, "roleID": roleID,
		"scope": list(scope), "grantedBy": grantedBy, "extra": values.holdAll(extra),
	})
}

// AssignInsert returns the statement that gives subjectID the role roleID at scope.
func (p RoleAssignmentSurface) AssignInsert(ctx context.Context, r *Runtime, assignmentID, subjectID, roleID string, scope []string, grantedBy string, extra map[string]any) (Statement, error) {
	return p.assign(ctx, r, "roleAssignment.assignInsert", assignmentID, subjectID, roleID, scope, grantedBy, extra)
}

// AssignTouchInsert returns the statement that gives subjectID the role roleID at scope, refreshing an assignment that
// is already there.
func (p RoleAssignmentSurface) AssignTouchInsert(ctx context.Context, r *Runtime, assignmentID, subjectID, roleID string, scope []string, grantedBy string, extra map[string]any) (Statement, error) {
	return p.assign(ctx, r, "roleAssignment.assignTouchInsert", assignmentID, subjectID, roleID, scope, grantedBy, extra)
}

// RevokeSQL returns the statement that revokes an assignment.
func (p RoleAssignmentSurface) RevokeSQL(ctx context.Context, r *Runtime) (string, error) {
	return get[string](ctx, r, "roleAssignment.revokeSQL", map[string]any{"surface": p})
}

// ListForRoleSQL returns the query that lists a role's active assignments.
func (p RoleAssignmentSurface) ListForRoleSQL(ctx context.Context, r *Runtime) (string, error) {
	return get[string](ctx, r, "roleAssignment.listForRoleSQL", map[string]any{"surface": p})
}

// ListForPrincipalSQL returns the query that lists a subject's active assignments.
func (p RoleAssignmentSurface) ListForPrincipalSQL(ctx context.Context, r *Runtime) (string, error) {
	return get[string](ctx, r, "roleAssignment.listForPrincipalSQL", map[string]any{"surface": p})
}

// ActivePredicate returns the condition an edge row meets while it is active, its columns prefixed by prefix.
func (g GrantSurface) ActivePredicate(ctx context.Context, r *Runtime, prefix string) (string, error) {
	return get[string](ctx, r, "levelGrant.activePredicate", map[string]any{"surface": g, "prefix": prefix})
}

// GrantInsert returns the statement that grants granteeID reach at levelID, expiring at expiresAt when it is not nil.
func (g GrantSurface) GrantInsert(ctx context.Context, r *Runtime, grantID, granteeID, levelID, grantedBy string, expiresAt any, extra map[string]any) (Statement, error) {
	values := &driverValues{}
	return values.statement(ctx, r, "levelGrant.grantInsert", map[string]any{
		"surface": g, "grantID": grantID, "granteeID": granteeID, "levelID": levelID, "grantedBy": grantedBy,
		"expiresAt": values.hold(expiresAt), "extra": values.holdAll(extra),
	})
}

// RevokeSQL returns the statement that revokes a grant.
func (g GrantSurface) RevokeSQL(ctx context.Context, r *Runtime) (string, error) {
	return get[string](ctx, r, "levelGrant.revokeSQL", map[string]any{"surface": g})
}

// ListSQL returns the query that lists a grantee's active grants.
func (g GrantSurface) ListSQL(ctx context.Context, r *Runtime) (string, error) {
	return get[string](ctx, r, "levelGrant.listSQL", map[string]any{"surface": g})
}

// IsReadMode reports whether mode makes a row readable by anyone.
func (p ResourceAccessSurface) IsReadMode(ctx context.Context, r *Runtime, mode string) (bool, error) {
	return get[bool](ctx, r, "resourceAccess.isReadMode", map[string]any{"surface": p, "mode": mode})
}

// GrantKindAllowed reports whether a grant may name a principal of kind.
func (p ResourceAccessSurface) GrantKindAllowed(ctx context.Context, r *Runtime, kind string) (bool, error) {
	return get[bool](ctx, r, "resourceAccess.grantKindAllowed", map[string]any{"surface": p, "kind": kind})
}

// ModeSQL returns the query that reads a row's visibility mode.
func (p ResourceAccessSurface) ModeSQL(ctx context.Context, r *Runtime) (string, error) {
	return get[string](ctx, r, "resourceAccess.modeSQL", map[string]any{"surface": p})
}

// SetVisibilitySQL returns the statement that sets a row's visibility mode.
func (p ResourceAccessSurface) SetVisibilitySQL(ctx context.Context, r *Runtime) (string, error) {
	return get[string](ctx, r, "resourceAccess.setVisibilitySQL", map[string]any{"surface": p})
}

// GrantInsert returns the statement that grants principalID of kind access to the row resourceID.
func (p ResourceAccessSurface) GrantInsert(ctx context.Context, r *Runtime, scope []string, resourceID, kind, principalID, access string) (Statement, error) {
	return (&driverValues{}).statement(ctx, r, "resourceAccess.grantInsert", map[string]any{
		"surface": p, "scope": list(scope), "resourceID": resourceID, "kind": kind, "principalID": principalID, "access": access,
	})
}

// RevokeDelete returns the statement that revokes that grant.
func (p ResourceAccessSurface) RevokeDelete(ctx context.Context, r *Runtime, resourceID, kind, principalID, access string) (Statement, error) {
	return (&driverValues{}).statement(ctx, r, "resourceAccess.revokeDelete", map[string]any{
		"surface": p, "resourceID": resourceID, "kind": kind, "principalID": principalID, "access": access,
	})
}

// ListGrantsSQL returns the query that lists a row's grants.
func (p ResourceAccessSurface) ListGrantsSQL(ctx context.Context, r *Runtime) (string, error) {
	return get[string](ctx, r, "resourceAccess.listGrantsSQL", map[string]any{"surface": p})
}

// ListGrantsArgs returns the arguments ListGrantsSQL takes for the row resourceID.
func (p ResourceAccessSurface) ListGrantsArgs(ctx context.Context, r *Runtime, resourceID string) ([]any, error) {
	args, err := get[[]*string](ctx, r, "resourceAccess.listGrantsArgs", map[string]any{"surface": p, "resourceID": resourceID})
	out := make([]any, len(args))
	for i, a := range args {
		if a != nil {
			out[i] = *a
		}
	}
	return out, err
}

// AccessorsSQL returns the query that lists who may read a row: the candidates, which AdmitsSQL decides between.
func (p ResourceAccessSurface) AccessorsSQL(ctx context.Context, r *Runtime) (string, error) {
	return get[string](ctx, r, "resourceAccess.accessorsSQL", map[string]any{"surface": p})
}

// AdmitsSQL returns the query that answers exactly whether a request carrying the given claims reads a row.
func (p ResourceAccessSurface) AdmitsSQL(ctx context.Context, r *Runtime) (string, error) {
	return get[string](ctx, r, "resourceAccess.admitsSQL", map[string]any{"surface": p})
}
