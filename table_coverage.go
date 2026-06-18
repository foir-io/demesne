package demesne

import "sort"

// Table coverage — the security-critical "which tables have NO row-level security?"
// question, for a `demesne coverage` drift check. A table the spec puts an OBJECT on is
// GOVERNED: it gets emitted RLS policies. A table the spec only REFERENCES — a
// role / grant / closure / group / membership store the generated definers read or the
// generated triggers maintain, but which carries no object of its own — is
// intentionally policy-free: it is reached only through the governed objects (via
// SECURITY DEFINER), never by the app role directly, so it correctly has no policy. A
// table in NEITHER set is UNGOVERNED: the spec does not mention it at all, so under the
// connection role it has no RLS — a likely gap (a forgotten or newly-added table) the
// operator must either model with an object or consciously exempt. Surfacing the
// ungoverned set is how an adopter keeps the spec in lockstep with a live schema.

// TableCoverage is the classification of a set of live database table names against
// the spec: which are governed (RLS), which are referenced-but-policy-free, and which
// are entirely ungoverned. Each list is sorted.
type TableCoverage struct {
	Governed   []string // has an object → emitted RLS policies
	Referenced []string // a spec-referenced store/edge with no object of its own (policy-free by design)
	Ungoverned []string // absent from the spec → no RLS; review
}

// TableCoverage classifies the given live table names against the spec. It is PURE —
// the CALLER introspects the database and passes the table list; the engine never
// connects. Tables the spec governs land in Governed; tables it references as a
// store/edge (but governs no object on) land in Referenced; everything else is
// Ungoverned (no RLS — the drift/gap signal).
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
