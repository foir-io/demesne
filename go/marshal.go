package demesne

import "encoding/json"

func slice[T any](xs []T) []T {
	if xs == nil {
		return []T{}
	}
	return xs
}

// MarshalJSON writes a nil list as an empty one, as the runtime reads it.
func (e ClaimEntry) MarshalJSON() ([]byte, error) {
	type plain ClaimEntry
	e.Subjects = slice(e.Subjects)
	return json.Marshal(plain(e))
}

// MarshalJSON writes nil lists as empty ones, as the runtime reads them.
func (c Claims) MarshalJSON() ([]byte, error) {
	type plain Claims
	c.Contract, c.Entries, c.Subjects, c.Levels = slice(c.Contract), slice(c.Entries), slice(c.Subjects), slice(c.Levels)
	return json.Marshal(plain(c))
}

// MarshalJSON writes a nil map as an empty one, as the runtime reads it.
func (p Principal) MarshalJSON() ([]byte, error) {
	type plain Principal
	p.Scopes = dict(p.Scopes)
	return json.Marshal(plain(p))
}

// MarshalJSON writes nil maps as empty ones, as the runtime reads them.
func (p PDP) MarshalJSON() ([]byte, error) {
	type plain PDP
	p.Policy, p.Ungoverned = dict(p.Policy), dict(p.Ungoverned)
	return json.Marshal(plain(p))
}

// MarshalJSON writes a nil list as an empty one, as the runtime reads it.
func (p Preset) MarshalJSON() ([]byte, error) {
	type plain Preset
	p.Set = slice(p.Set)
	return json.Marshal(plain(p))
}

// MarshalJSON writes a nil list as an empty one, as the runtime reads it.
func (i Implication) MarshalJSON() ([]byte, error) {
	type plain Implication
	i.Set = slice(i.Set)
	return json.Marshal(plain(i))
}

// MarshalJSON writes nil lists as empty ones, as the runtime reads them.
func (v Vocabulary) MarshalJSON() ([]byte, error) {
	type plain Vocabulary
	v.Permissions, v.Presets, v.Rank = slice(v.Permissions), slice(v.Presets), slice(v.Rank)
	return json.Marshal(plain(v))
}

// MarshalJSON writes a nil list as an empty one, as the runtime reads it.
func (h HoldsResolver) MarshalJSON() ([]byte, error) {
	type plain HoldsResolver
	h.ScopeCols = slice(h.ScopeCols)
	return json.Marshal(plain(h))
}

// MarshalJSON writes nil lists as empty ones, as the runtime reads them.
func (a RoleAssignment) MarshalJSON() ([]byte, error) {
	type plain RoleAssignment
	a.Scope, a.Permissions = slice(a.Scope), slice(a.Permissions)
	return json.Marshal(plain(a))
}

// MarshalJSON writes nil lists as empty ones, as the runtime reads them.
func (p RoleAssignmentSurface) MarshalJSON() ([]byte, error) {
	type plain RoleAssignmentSurface
	p.ScopeCols, p.ExtraCols = slice(p.ScopeCols), slice(p.ExtraCols)
	return json.Marshal(plain(p))
}

// MarshalJSON writes a nil list as an empty one, as the runtime reads it.
func (g GrantSurface) MarshalJSON() ([]byte, error) {
	type plain GrantSurface
	g.ExtraCols = slice(g.ExtraCols)
	return json.Marshal(plain(g))
}

// MarshalJSON writes nil lists as empty ones, as the runtime reads them.
func (p ResourceAccessSurface) MarshalJSON() ([]byte, error) {
	type plain ResourceAccessSurface
	p.ScopeCols, p.ReadModes, p.GrantKinds = slice(p.ScopeCols), slice(p.ReadModes), slice(p.GrantKinds)
	return json.Marshal(plain(p))
}
