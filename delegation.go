package demesne

import "sort"

type DelegationCap struct {
	Allowed bool

	Unknown []string

	Excess []string
}

func (v *Vocabulary) CapGrant(held, requested []string) DelegationCap {
	inVocab := make(map[string]bool, len(v.Permissions))
	for _, p := range v.Permissions {
		inVocab[p] = true
	}
	heldSet := make(map[string]bool, len(held))
	for _, p := range held {
		heldSet[p] = true
	}
	var unknown, excess []string
	seenU, seenE := map[string]bool{}, map[string]bool{}
	for _, p := range requested {
		switch {
		case !inVocab[p]:
			if !seenU[p] {
				seenU[p] = true
				unknown = append(unknown, p)
			}
		case !heldSet[p]:

			if !seenE[p] {
				seenE[p] = true
				excess = append(excess, p)
			}
		}
	}
	sort.Strings(unknown)
	sort.Strings(excess)
	return DelegationCap{Allowed: len(unknown) == 0 && len(excess) == 0, Unknown: unknown, Excess: excess}
}
