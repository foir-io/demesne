package demesne

import (
	"fmt"
	"strings"
)

// Level-grant management (Layer 3, EID-334) — the control-plane WRITE surface over a
// `grant … via edge` store (operator / impersonation reach), the dual of the reach
// definer the engine already compiles from the grant. A grant edge confers reach into
// a topology level's subtree to a grantee while it holds an ACTIVE row; the engine
// compiles the READ (auth.<table>_reach, a SECURITY DEFINER EXISTS over the edge with
// the active/expiry predicate) but never the writes that MAINTAIN the edge — issue a
// grant, revoke it, list grants — so every adopter hand-writes them (Foir:
// GrantImpersonation / RevokeImpersonation / ListImpersonationGrants over hand-authored
// sqlc). They are derivable from the same grant declaration, exactly as the
// role-assignment writes are in role_assignment_runtime.go (the sibling this mirrors).
//
// Same read/compute boundary and moat: these BUILD SQL + ordered args; the CALLER
// executes them. The grant edge is the control-plane root-of-trust — its writes run on
// the privileged (BYPASSRLS) pool gated by an eligibility check the adopter owns (Foir:
// is_platform_admin / "is staff"), since the edge deliberately exposes NO write policy
// to the app role (a self-grant must be impossible). So unlike the role-assignment
// surface (whose moat is the role_assignments object's RLS), the level-grant moat is
// the adopter's eligibility gate around these statements; this layer SHAPES the
// statements from the grant declaration and never decides who may call them.
//
// GENERIC by construction. The active predicate is built from the grant's own
// ActiveCol / ExpiresCol — byte-for-byte the conjuncts the reach definer uses
// (`<active> IS NULL`, `<expires> > now()`), so management and enforcement agree on
// "active" by construction. It bakes in no adopter policy: the eligibility gate, a
// required justification, and any other edge columns are the adopter's — extra columns
// are passed to GrantInsert as ad-hoc name→value pairs, not modelled in the grammar.
//
// Target-neutral: GrantSurface is plain exported data and the builders return strings +
// ordered args. Nothing names a tenant/project/customer/operator — the table, columns
// and level are spec-declared (EID-267 / EID-315).

// GrantSurface projects a `grant … via edge` declaration into the management write
// layout: the edge table + the columns the issue/revoke/list ops touch (the reach
// columns plus the optional audit columns). One source of truth for the layout, so a
// handler never re-derives it and cannot drift from the reach definer.
type GrantSurface struct {
	Name       string // the grant name
	Level      string // the topology level it confers reach at
	Table      string // the edge store
	GranteeCol string // the granted-subject id column
	LevelCol   string // the level-scope column (e.g. tenant_id)
	ActiveCol  string // revoked filter ("" if none; NULL = active)
	ExpiresCol string // expiry ("" if none; > now() = active)
	PK         string // the edge's primary-key column (the issue id / revoke key)
	// Optional audit columns ("" when the grant declares none).
	GrantedByCol string // grantor principal id
	RevokedByCol string // revoker principal id
	CreatedAtCol string // audit timestamp (the list order)
	// ExtraCols are adopter edge columns the grammar does not model (e.g. an audited
	// justification): WRITTEN by GrantInsert (value from its `extra` map) and PROJECTED
	// in every RETURNING/SELECT, in declaration order — so a response that echoes them
	// is not silently emptied.
	ExtraCols []string
}

// GrantSurface builds the management surface for a named grant. Errors when the spec
// has no such grant.
func (s *Spec) GrantSurface(name string) (*GrantSurface, error) {
	g := s.grantByName(name)
	if g == nil {
		return nil, fmt.Errorf("GrantSurface: no grant %q in the spec", name)
	}
	return &GrantSurface{
		Name:         g.Name,
		Level:        g.Level,
		Table:        g.Table,
		GranteeCol:   g.GranteeCol,
		LevelCol:     g.LevelCol,
		ActiveCol:    g.ActiveCol,
		ExpiresCol:   g.ExpiresCol,
		PK:           g.grantPK(),
		GrantedByCol: g.GrantedByCol,
		RevokedByCol: g.RevokedByCol,
		CreatedAtCol: g.CreatedAtCol,
		ExtraCols:    append([]string(nil), g.ExtraCols...),
	}, nil
}

// activePredicate renders the "this grant is active" condition from the declared
// ActiveCol / ExpiresCol, prefixed by `prefix` (e.g. "" or "ig."): `<active> IS NULL`
// AND `<expires> > now()`, whichever are declared. The SAME conjuncts the reach
// definer uses, so management and enforcement agree on "active". With neither column
// declared a grant is always active, so this returns "TRUE".
func (g *GrantSurface) activePredicate(prefix string) string {
	var conj []string
	if g.ActiveCol != "" {
		conj = append(conj, fmt.Sprintf("%s%s IS NULL", prefix, g.ActiveCol))
	}
	if g.ExpiresCol != "" {
		conj = append(conj, fmt.Sprintf("%s%s > now()", prefix, g.ExpiresCol))
	}
	if len(conj) == 0 {
		return "TRUE"
	}
	return strings.Join(conj, " AND ")
}

// grantCols is the grant-row projection in canonical order: pk, grantee, level, then
// whichever audit/validity columns the grant declares (granted_by, expires, created_at,
// active, revoked_by), then the adopter ExtraCols (declaration order). What GrantInsert
// RETURNs and ListSQL selects, so a caller scans one stable column order — and the extra
// columns it writes are echoed back, not dropped.
func (g *GrantSurface) grantCols() []string {
	cols := []string{g.PK, g.GranteeCol, g.LevelCol}
	for _, c := range []string{g.GrantedByCol, g.ExpiresCol, g.CreatedAtCol, g.ActiveCol, g.RevokedByCol} {
		if c != "" {
			cols = append(cols, c)
		}
	}
	return append(cols, g.ExtraCols...)
}

// GrantInsert builds the INSERT that issues a grant — the grantee reaches the given
// level node — and its ordered args. It writes the pk, grantee, level, and (when the
// grant declares them) the grantor and expiry; the audit timestamp is left to the
// table default and the active/revoker columns to NULL (a fresh grant is active).
// `extra` supplies the values for the declared ExtraCols (keyed by column name; a
// declared column absent from the map is written NULL); keys not in ExtraCols are
// ignored — an extra column is written AND projected only when it is declared, so the
// two never drift. RETURNING projects grantCols (which includes ExtraCols). The caller
// runs it behind its eligibility gate (the level-grant moat). Mirrors
// role_assignment_runtime.go's AssignInsert.
//
// Args order: grantID, granteeID, levelID, [grantedBy], [expiresAt], then the ExtraCols
// values in declaration order.
func (g *GrantSurface) GrantInsert(grantID, granteeID, levelID, grantedBy string, expiresAt any, extra map[string]any) (string, []any) {
	cols := []string{g.PK, g.GranteeCol, g.LevelCol}
	args := []any{grantID, granteeID, levelID}
	if g.GrantedByCol != "" {
		cols = append(cols, g.GrantedByCol)
		args = append(args, grantedBy)
	}
	if g.ExpiresCol != "" {
		cols = append(cols, g.ExpiresCol)
		args = append(args, expiresAt)
	}
	for _, c := range g.ExtraCols {
		cols = append(cols, c)
		args = append(args, extra[c])
	}
	ph := make([]string, len(cols))
	for i := range ph {
		ph[i] = fmt.Sprintf("$%d", i+1)
	}
	sql := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s) RETURNING %s",
		g.Table, strings.Join(cols, ", "), strings.Join(ph, ", "), strings.Join(g.grantCols(), ", "))
	return sql, args
}

// RevokeSQL builds the revoke, keyed by primary key. When the grant declares an active
// (revoked) column it is a SOFT-revoke that stamps it (and the revoker, when declared)
// on an ACTIVE grant — `UPDATE … SET <active> = now()[, <revoked_by> = $2] WHERE <pk> =
// $1 AND <active> IS NULL` — idempotent and original-revoker-preserving, RETURNING the
// row. With no active column there is nothing to stamp, so it is a hard `DELETE … WHERE
// <pk> = $1`. $1 = grant id; $2 = revoker (only when a RevokedByCol is declared). The
// arg order (id first) is the engine's uniform revoke convention.
func (g *GrantSurface) RevokeSQL() string {
	if g.ActiveCol == "" {
		return fmt.Sprintf("DELETE FROM %s WHERE %s = $1", g.Table, g.PK)
	}
	set := fmt.Sprintf("%s = now()", g.ActiveCol)
	if g.RevokedByCol != "" {
		set += fmt.Sprintf(", %s = $2", g.RevokedByCol)
	}
	return fmt.Sprintf("UPDATE %s SET %s WHERE %s = $1 AND %s IS NULL RETURNING %s",
		g.Table, set, g.PK, g.ActiveCol, strings.Join(g.grantCols(), ", "))
}

// ListSQL lists grants with three optional filters, projected as grantCols, newest
// first when a created-at column is declared: $1 = grantee (NULL ⇒ any), $2 = level id
// (NULL ⇒ any), $3 = active-only (true ⇒ only currently-active grants, via the same
// active predicate the reach definer uses). Reproduces the hand-written grant list.
func (g *GrantSurface) ListSQL() string {
	sql := fmt.Sprintf(
		"SELECT %s FROM %s WHERE ($1::text IS NULL OR %s = $1) AND ($2::text IS NULL OR %s = $2) AND (NOT $3::boolean OR (%s))",
		strings.Join(g.grantCols(), ", "), g.Table, g.GranteeCol, g.LevelCol, g.activePredicate(""))
	if g.CreatedAtCol != "" {
		sql += fmt.Sprintf(" ORDER BY %s DESC", g.CreatedAtCol)
	}
	return sql
}
