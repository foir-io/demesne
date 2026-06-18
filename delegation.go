package demesne

import "sort"

// Delegation cap (Layer 3, EID-334) — the generic ReBAC guard "you cannot grant a
// permission you do not hold." Authoring or assigning a role lets a grantor confer
// authority on someone else; without a cap, an in-scope grantor could mint a role
// carrying MORE than the grantor holds (privilege escalation). The guard is generic
// ReBAC policy, not adopter policy — Foir hand-wrote it (authz.AuthorizeAdminRoleGrant:
// adminperm.Unknown for vocabulary validity + adminperm.Subset for the intersection),
// and so does every adopter. It is derivable from the vocabulary (the valid permission
// set) + the grantor's held set, so the engine computes it.
//
// Pure compute, no SQL, no policy re-evaluation — it FOLDS two sets the caller already
// has: the vocabulary's permission list (the engine owns it) and the grantor's
// effective held set, which is exactly the EffectivePerms the holds-resolver (Layer 2)
// resolves. The two compose directly:
//
//	eff, _ := resolver.Resolve(assignments, scope)
//	cap := resolver.Vocabulary().CapGrant(eff.Permissions(), requested)
//	// cap.Unknown -> "not a real permission" (invalid argument)
//	// cap.Excess  -> "you don't hold it"     (permission denied)
//
// GENERIC by construction. It owns ONLY the intersection cap + vocabulary validity —
// the two pieces that are the same for every adopter. The OTHER gates a real grant
// guard composes are adopter policy, NOT baked in: a rank FLOOR ("must be at least
// project_admin to author roles at all" — expressible with RankOf / PresetsAtOrAbove),
// a higher-plane BYPASS (platform staff skip the cap), and the principal-kind check.
// A caller layers those around CapGrant (see the consumer parity test, which
// reconstructs Foir's full AuthorizeAdminRoleGrant from CapGrant + the rank ladder +
// that glue). Nothing here names a tenant/project/customer/role — the vocabulary is
// spec-declared (EID-267 / EID-315). Sorted outputs use Go byte order; a cross-target
// port pins the same comparator (as the rest of the runtime glue does).

// DelegationCap is the outcome of an intersection-cap check: whether a grantor holding
// `held` may confer `requested`, and — when not — exactly WHY, so a caller renders a
// precise denial. Unknown and Excess are disjoint and each carries its own reason.
type DelegationCap struct {
	// Allowed is true iff Unknown and Excess are both empty.
	Allowed bool
	// Unknown lists the requested permissions that are NOT in the vocabulary at all
	// (a typo / a stale key) — fail-closed, sorted, de-duplicated.
	Unknown []string
	// Excess lists the requested permissions that ARE valid vocabulary permissions but
	// the grantor does NOT hold — the cap violation ("can't grant what you don't
	// hold") — sorted, de-duplicated.
	Excess []string
}

// CapGrant computes the delegation cap: a grantor holding `held` may confer
// `requested` iff every requested permission is (a) a real permission of this
// vocabulary AND (b) one the grantor itself holds. It reports the two failure classes
// separately — Unknown (outside the vocabulary) and Excess (valid but unheld) — so a
// caller can map them to distinct errors (Foir: invalid-argument vs permission-denied)
// in whatever precedence it wants. An empty `requested` is vacuously allowed (a role
// granting nothing escalates nothing). This reproduces the adopter's hand-written
// vocabulary-validity + permission-intersection decision exactly.
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
			// A VALID permission the grantor does not hold — the cap violation.
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
