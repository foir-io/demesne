package demesne

import "sort"

type TableCoverage struct {
	Governed   []string
	Referenced []string
	Ungoverned []string
}

func (s *Spec) TableCoverage(dbTables []string) TableCoverage {
	governed := map[string]bool{}
	for _, o := range s.Objects {
		governed[o.Table] = true
	}

	referenced := map[string]bool{}
	add := func(t string) {
		if t != "" && !governed[t] {
			referenced[t] = true
		}
	}
	for _, rs := range s.RoleStores {
		add(rs.Assignments)
		add(rs.RolesTable)
	}
	for _, g := range s.Grants {
		add(g.Table)
	}
	for _, sub := range s.Subjects {
		if sub.Membership != nil {
			add(sub.Membership.Table)
		}
	}
	for _, o := range s.Objects {
		for _, r := range o.Relations {
			switch repr := r.Repr.(type) {
			case ViaEdge:
				add(repr.Table)
			case ViaComposition:
				add(repr.Table)
			case ViaClosure:
				add(repr.Closure)
				add(repr.Base)
			case ViaGroup:
				add(repr.Closure)
				add(repr.Edge)
			case ViaGrant:
				add(repr.Table)
			}
		}
	}

	var cov TableCoverage
	for _, t := range dbTables {
		switch {
		case governed[t]:
			cov.Governed = append(cov.Governed, t)
		case referenced[t]:
			cov.Referenced = append(cov.Referenced, t)
		default:
			cov.Ungoverned = append(cov.Ungoverned, t)
		}
	}
	sort.Strings(cov.Governed)
	sort.Strings(cov.Referenced)
	sort.Strings(cov.Ungoverned)
	return cov
}
