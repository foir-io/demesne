package demesne

import (
	"fmt"
	"strings"
)

// Role-assignment management (Layer 3, EID-334) — the control-plane WRITE surface
// over the rolestore, the dual of the holds-resolver's READ. The engine already
// compiles the role-resolution READ definers (is_<level>_admin, …) and the
// holds-resolver from the rolestore; what it never generated is the writes that
// MAINTAIN that store — assign a role to a principal, revoke an assignment, list
// them — so every adopter hand-writes them (Foir: AssignRole / RevokeRoleAssignment /
// ListRoleAssignments* over hand-authored sqlc queries). They are mechanically
// derivable from the same rolestore declaration, exactly as the per-object ACL
// writes are derived in access_runtime.go (the shipped template this mirrors).
//
// Same read/compute boundary, same moat: these BUILD SQL + ordered args; the CALLER
// executes them under the principal's claims (db.WithRLS). The role_assignments
// table is itself a governed object in the spec, so its RLS (containment / the
// @scoped write rule) is the write moat — an out-of-scope caller's INSERT/UPDATE
// matches no row / is denied. This layer never re-evaluates that policy; it only
// SHAPES the statements from the rolestore, so they cannot drift from the columns
// the read definers resolve over. The intersection-cap delegation guard ("you can't
// grant a role you don't hold") is a SEPARATE primitive (EID-334 #4); this layer is
// the mechanical assign/revoke/list, not the delegation policy.
//
// GENERIC by construction. It emits the writes the rolestore grammar implies and
// bakes in NO adopter policy: it does not encode an RP/client secondary scope, an
// idempotent reactivate-on-reassign upsert over an adopter-chosen unique index, or a
// disabled-role admission filter — those are the adopter's policy (Foir layers all
// three), composed around these statements, not part of the rolestore grammar. So
// for an adopter that adds them the generated write is the CORE the adopter extends
// (the documented "management delta"), the same contract as the holds-resolver's
// read-filter delta.
//
// Target-neutral: RoleAssignmentSurface is plain exported data and the builders
// return strings + ordered args, so a TypeScript emitter reproduces them from the
// same projection. Nothing names a tenant/project/customer/role — the table, columns
// and kind constant are all spec-declared (EID-267 / EID-315). KindVal is interpolated
// as a SQL string literal (a compile-time spec constant — the only runtime values are
// bound), matching the inlined kind literal the read definers + holds-resolver use.

// RoleAssignmentSurface projects a rolestore into the management write layout: the
// assignment table + the columns the assign/revoke/list ops touch (the read columns
// the holds-resolver shares, plus the optional audit columns). One source of truth
// for the layout, so a handler never re-derives it (and cannot drift from the read
// definers compiled over the same store).
type RoleAssignmentSurface struct {
	Assignments string   // the role-assignment table
	PK          string   // its primary-key column (the assign id / revoke key)
	KindCol     string   // principal-kind column
	KindVal     string   // its required value (inlined; the assignment is for this kind)
	SubjectCol  string   // principal-id column
	RoleCol     string   // FK column → RolesTable
	ScopeCols   []string // scope columns root→leaf, written on a new assignment
	RevokedCol  string   // active filter (an active assignment has it NULL)
	// Optional audit columns ("" when the rolestore declares none).
	GrantedAtCol string // grant timestamp (set to now() on (re)assign / ordered-by on list)
	GrantedByCol string // grantor principal id
	RevokedByCol string // revoker principal id
	// Roles join (for ListForPrincipal — the assignment's role key + materialized perms).
	RolesTable string
	RolesID    string
	KeyCol     string
	PermsCol   string
}

// RoleAssignmentSurface builds the management surface for a named rolestore (pass ""
// for the spec's sole rolestore). Errors when the spec has no such rolestore.
func (s *Spec) RoleAssignmentSurface(rolestore string) (*RoleAssignmentSurface, error) {
	var rs *RoleStore
	if rolestore == "" {
		rs = roleStoreByName(s)
	} else {
		for _, r := range s.RoleStores {
			if r.Name == rolestore {
				rs = r
				break
			}
		}
	}
	if rs == nil {
		if rolestore == "" {
			return nil, fmt.Errorf("RoleAssignmentSurface: the spec declares no rolestore")
		}
		return nil, fmt.Errorf("RoleAssignmentSurface: no rolestore %q in the spec", rolestore)
	}
	return &RoleAssignmentSurface{
		Assignments:  rs.Assignments,
		PK:           rs.assignmentPK(),
		KindCol:      rs.KindCol,
		KindVal:      rs.KindVal,
		SubjectCol:   rs.SubjectCol,
		RoleCol:      rs.RoleCol,
		ScopeCols:    append([]string(nil), rs.ScopeCols...),
		RevokedCol:   rs.RevokedCol,
		GrantedAtCol: rs.GrantedAtCol,
		GrantedByCol: rs.GrantedByCol,
		RevokedByCol: rs.RevokedByCol,
		RolesTable:   rs.RolesTable,
		RolesID:      rs.RolesID,
		KeyCol:       rs.KeyCol,
		PermsCol:     rs.PermsCol,
	}, nil
}

// assignmentCols is the assignment-row projection in canonical order: pk, kind,
// subject, role, scope cols (root→leaf), then whichever audit columns the rolestore
// declares (granted_at, granted_by, revoked, revoked_by). It is what AssignInsert
// RETURNs and ListForRole selects, so a caller scans one stable column order.
func (r *RoleAssignmentSurface) assignmentCols() []string {
	cols := []string{r.PK, r.KindCol, r.SubjectCol, r.RoleCol}
	cols = append(cols, r.ScopeCols...)
	for _, c := range []string{r.GrantedAtCol, r.GrantedByCol, r.RevokedCol, r.RevokedByCol} {
		if c != "" {
			cols = append(cols, c)
		}
	}
	return cols
}

// AssignInsert builds the INSERT that confers a role on a principal at a scope, and
// its ordered args. The row carries the kind constant (inlined), the supplied
// assignment id, subject, role, the scope values (root→leaf, matching ScopeCols),
// and — when the rolestore declares a grantor column — grantedBy; granted_at is left
// to the table default (set on the database side), matching the hand-written path.
// RETURNING projects assignmentCols. The role_assignments object's own RLS is the
// write moat (an out-of-scope INSERT is denied). Mirrors access_runtime.go's
// GrantInsert.
//
// Args order: assignmentID, KindVal, subjectID, roleID, scope…, [grantedBy].
func (r *RoleAssignmentSurface) AssignInsert(assignmentID, subjectID, roleID string, scope []string, grantedBy string) (string, []any) {
	cols := []string{r.PK, r.KindCol, r.SubjectCol, r.RoleCol}
	args := []any{assignmentID, r.KindVal, subjectID, roleID}
	for i, c := range r.ScopeCols {
		cols = append(cols, c)
		if i < len(scope) {
			args = append(args, scope[i])
		} else {
			args = append(args, nil)
		}
	}
	if r.GrantedByCol != "" {
		cols = append(cols, r.GrantedByCol)
		args = append(args, grantedBy)
	}
	ph := make([]string, len(cols))
	for i := range ph {
		ph[i] = fmt.Sprintf("$%d", i+1)
	}
	sql := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s) RETURNING %s",
		r.Assignments, strings.Join(cols, ", "), strings.Join(ph, ", "), strings.Join(r.assignmentCols(), ", "))
	return sql, args
}

// RevokeSQL builds the soft-revoke: an UPDATE that stamps the revoked column (and the
// revoker, when declared) on an ACTIVE assignment, keyed by primary key. $1 = the
// assignment id; $2 = the revoker id when a RevokedByCol is declared. The
// `AND <revoked> IS NULL` guard makes it idempotent (re-revoking touches 0 rows) and
// preserves the original revoker. Rides the role_assignments RLS (an out-of-scope
// UPDATE matches 0 rows). Reproduces the hand-written soft-revoke exactly.
func (r *RoleAssignmentSurface) RevokeSQL() string {
	set := fmt.Sprintf("%s = now()", r.RevokedCol)
	if r.RevokedByCol != "" {
		set += fmt.Sprintf(", %s = $2", r.RevokedByCol)
	}
	return fmt.Sprintf("UPDATE %s SET %s WHERE %s = $1 AND %s IS NULL",
		r.Assignments, set, r.PK, r.RevokedCol)
}

// ListForRoleSQL lists every assignment of a role (active AND revoked — an audit
// view), projected as assignmentCols, newest first when a granted-at column is
// declared. $1 = role id (matched against the assignment's role FK). Reproduces the
// hand-written by-role list.
func (r *RoleAssignmentSurface) ListForRoleSQL() string {
	sql := fmt.Sprintf("SELECT %s FROM %s WHERE %s = $1",
		strings.Join(r.assignmentCols(), ", "), r.Assignments, r.RoleCol)
	if r.GrantedAtCol != "" {
		sql += fmt.Sprintf(" ORDER BY %s DESC", r.GrantedAtCol)
	}
	return sql
}

// ListForPrincipalSQL lists a principal's ACTIVE assignments joined to each role's
// key (and materialized permissions, when declared) — the management by-principal
// view. $1 = principal id; the kind is inlined (the compile-time constant, as in the
// holds-resolver's AssignmentsSQL). The active filter is `<revoked> IS NULL`; an
// adopter's further admission policy (e.g. excluding a disabled role) is composed
// around this read, not baked in (the read-filter delta).
//
// Scan order: a.PK, a.SubjectCol, a.RoleCol, [a.GrantedAtCol], [a.GrantedByCol],
// r.KeyCol, [r.PermsCol].
func (r *RoleAssignmentSurface) ListForPrincipalSQL() string {
	cols := []string{"a." + r.PK, "a." + r.SubjectCol, "a." + r.RoleCol}
	for _, c := range []string{r.GrantedAtCol, r.GrantedByCol} {
		if c != "" {
			cols = append(cols, "a."+c)
		}
	}
	cols = append(cols, "r."+r.KeyCol)
	if r.PermsCol != "" {
		cols = append(cols, "r."+r.PermsCol)
	}
	return fmt.Sprintf(
		"SELECT %s FROM %s a JOIN %s r ON r.%s = a.%s WHERE a.%s = '%s' AND a.%s = $1 AND a.%s IS NULL",
		strings.Join(cols, ", "),
		r.Assignments, r.RolesTable, r.RolesID, r.RoleCol,
		r.KindCol, r.KindVal, r.SubjectCol, r.RevokedCol)
}
