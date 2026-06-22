package demesne

import (
	"fmt"
	"strings"
)

type GrantSurface struct {
	Name       string
	Level      string
	Table      string
	GranteeCol string
	LevelCol   string
	ActiveCol  string
	ExpiresCol string
	PK         string

	GrantedByCol string
	RevokedByCol string
	CreatedAtCol string

	ExtraCols []string
}

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

func (g *GrantSurface) grantCols() []string {
	cols := []string{g.PK, g.GranteeCol, g.LevelCol}
	for _, c := range []string{g.GrantedByCol, g.ExpiresCol, g.CreatedAtCol, g.ActiveCol, g.RevokedByCol} {
		if c != "" {
			cols = append(cols, c)
		}
	}
	return append(cols, g.ExtraCols...)
}

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

func (g *GrantSurface) ListSQL() string {
	sql := fmt.Sprintf(
		"SELECT %s FROM %s WHERE ($1::text IS NULL OR %s = $1) AND ($2::text IS NULL OR %s = $2) AND (NOT $3::boolean OR (%s))",
		strings.Join(g.grantCols(), ", "), g.Table, g.GranteeCol, g.LevelCol, g.activePredicate(""))
	if g.CreatedAtCol != "" {
		sql += fmt.Sprintf(" ORDER BY %s DESC", g.CreatedAtCol)
	}
	return sql
}
