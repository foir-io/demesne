package demesne

import (
	"fmt"
	"sort"
)

type ClaimEntry struct {
	Key      string
	Level    string
	Subjects []string
}

func (s *Spec) ClaimsContractEntries() ([]ClaimEntry, error) {
	chain, err := s.nonVirtualChain()
	if err != nil {
		return nil, err
	}
	byKey := map[string]*ClaimEntry{}
	entry := func(k string) *ClaimEntry {
		if e := byKey[k]; e != nil {
			return e
		}
		e := &ClaimEntry{Key: k}
		byKey[k] = e
		return e
	}
	for _, l := range chain {
		entry(l.claimKey()).Level = l.Name
	}
	for _, sub := range s.Subjects {
		if sub.Identifies != "" {
			e := entry(sub.Identifies)
			e.Subjects = append(e.Subjects, sub.Name)
		}
	}
	out := make([]ClaimEntry, 0, len(byKey))
	for _, e := range byKey {
		sort.Strings(e.Subjects)
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

type Principal struct {
	Subject string
	ID      string
	Scopes  map[string]string
}

func (s *Spec) BuildClaims(p Principal) (map[string]string, error) {
	sub := s.subjectByName(p.Subject)
	if sub == nil {
		return nil, fmt.Errorf("BuildClaims: no subject %q in the spec", p.Subject)
	}
	values := map[string]string{}
	if p.ID != "" {
		if sub.Identifies == "" {
			return nil, fmt.Errorf("BuildClaims: subject %q has no identity key (`identifies`) but an id was supplied", p.Subject)
		}
		values[sub.Identifies] = p.ID
	}

	levels := make([]string, 0, len(p.Scopes))
	for name := range p.Scopes {
		levels = append(levels, name)
	}
	sort.Strings(levels)
	for _, name := range levels {
		l := s.Topology.LevelByName(name)
		if l == nil {
			return nil, fmt.Errorf("BuildClaims: subject %q presents a scope for unknown level %q", p.Subject, name)
		}
		if l.Virtual {
			return nil, fmt.Errorf("BuildClaims: level %q is virtual (no scope claim) — it cannot carry a scope id", name)
		}
		values[l.claimKey()] = p.Scopes[name]
	}
	return values, nil
}

func (s *Spec) MintClaimsFor(p Principal) (string, error) {
	values, err := s.BuildClaims(p)
	if err != nil {
		return "", err
	}
	return s.MintClaims(values)
}

func (s *Spec) claimRole() string {
	if s.Claims != nil && s.Claims.Role != "" {
		return s.Claims.Role
	}
	return "authenticated"
}

func (s *Spec) ConnectionRole() string { return s.claimRole() }

func (s *Spec) SetRoleSQL(local bool) string {
	kw := "SET ROLE"
	if local {
		kw = "SET LOCAL ROLE"
	}
	return fmt.Sprintf("%s %s", kw, s.claimRole())
}

func (s *Spec) SessionSetupSQL(local bool) []string {
	return []string{s.SetRoleSQL(local), s.ClaimsSetSQL(local)}
}
