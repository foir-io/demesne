package demesne

import (
	"fmt"
	"strings"
)

type RoleAssignmentSurface struct {
	Assignments string
	PK          string
	KindCol     string
	KindVal     string
	SubjectCol  string
	RoleCol     string
	ScopeCols   []string
	RevokedCol  string

	GrantedAtCol string
	GrantedByCol string
	RevokedByCol string

	ExtraCols []string

	RolesTable string
	RolesID    string
	KeyCol     string
	PermsCol   string
}

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
		ExtraCols:    append([]string(nil), rs.ExtraCols...),
		RolesTable:   rs.RolesTable,
		RolesID:      rs.RolesID,
		KeyCol:       rs.KeyCol,
		PermsCol:     rs.PermsCol,
	}, nil
}

func (r *RoleAssignmentSurface) assignmentCols() []string {
	cols := []string{r.PK, r.KindCol, r.SubjectCol, r.RoleCol}
	cols = append(cols, r.ScopeCols...)
	for _, c := range []string{r.GrantedAtCol, r.GrantedByCol, r.RevokedCol, r.RevokedByCol} {
		if c != "" {
			cols = append(cols, c)
		}
	}
	return append(cols, r.ExtraCols...)
}

func (r *RoleAssignmentSurface) AssignInsert(assignmentID, subjectID, roleID string, scope []string, grantedBy string, extra map[string]any) (string, []any) {
	return r.assignSQL(false, assignmentID, subjectID, roleID, scope, grantedBy, extra)
}

func (r *RoleAssignmentSurface) AssignTouchInsert(assignmentID, subjectID, roleID string, scope []string, grantedBy string, extra map[string]any) (string, []any) {
	return r.assignSQL(true, assignmentID, subjectID, roleID, scope, grantedBy, extra)
}

func (r *RoleAssignmentSurface) assignSQL(touch bool, assignmentID, subjectID, roleID string, scope []string, grantedBy string, extra map[string]any) (string, []any) {
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
	for _, c := range r.ExtraCols {
		cols = append(cols, c)
		args = append(args, extra[c])
	}
	ph := make([]string, len(cols))
	for i := range ph {
		ph[i] = fmt.Sprintf("$%d", i+1)
	}
	conflict := ""
	if touch {
		conflict = " " + r.touchClause()
	}
	sql := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)%s RETURNING %s",
		r.Assignments, strings.Join(cols, ", "), strings.Join(ph, ", "), conflict, strings.Join(r.assignmentCols(), ", "))
	return sql, args
}

func (r *RoleAssignmentSurface) touchClause() string {
	bare := []string{r.KindCol, r.SubjectCol, r.RoleCol}
	nullable := append(append([]string(nil), r.ScopeCols...), r.ExtraCols...)
	var sets []string
	if r.RevokedCol != "" {
		sets = append(sets, r.RevokedCol+" = NULL")
	}
	if r.RevokedByCol != "" {
		sets = append(sets, r.RevokedByCol+" = NULL")
	}
	if r.GrantedAtCol != "" {
		sets = append(sets, r.GrantedAtCol+" = now()")
	}
	if r.GrantedByCol != "" {
		sets = append(sets, fmt.Sprintf("%s = EXCLUDED.%s", r.GrantedByCol, r.GrantedByCol))
	}
	return touchOnConflict(bare, nullable, sets)
}

func (r *RoleAssignmentSurface) RevokeSQL() string {
	set := fmt.Sprintf("%s = now()", r.RevokedCol)
	if r.RevokedByCol != "" {
		set += fmt.Sprintf(", %s = $2", r.RevokedByCol)
	}
	return fmt.Sprintf("UPDATE %s SET %s WHERE %s = $1 AND %s IS NULL",
		r.Assignments, set, r.PK, r.RevokedCol)
}

func (r *RoleAssignmentSurface) ListForRoleSQL() string {
	sql := fmt.Sprintf("SELECT %s FROM %s WHERE %s = $1",
		strings.Join(r.assignmentCols(), ", "), r.Assignments, r.RoleCol)
	if r.GrantedAtCol != "" {
		sql += fmt.Sprintf(" ORDER BY %s DESC", r.GrantedAtCol)
	}
	return sql
}

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
