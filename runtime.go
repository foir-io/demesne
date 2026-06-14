package demesne

import (
	"encoding/json"
	"fmt"
	"sort"
)

// Runtime glue (WS5, EID-265). The engine compiles enforcement into the database
// (RLS) and emits a contract + a verb map; a real deployment still needs a little
// runtime to (a) MINT the claims a session presents, (b) ENFORCE the verb PDP at
// the request boundary (RLS can't see verbs), and (c) POINT-CHECK a single
// decision for UI affordances. These helpers are that glue — and only glue: they
// are stdlib-pure and they NEVER re-evaluate policy in app code. The point-check
// in particular returns a QUERY the caller runs against the database, so the real
// RLS predicate decides — this is emphatically NOT a parallel row-reachability
// evaluator (the Zanzibar Check service the moat rejects).

// --- (a) claims / session minting -------------------------------------------

func (s *Spec) claimSetting() (setting, cast string) {
	if s.Claims != nil {
		return s.Claims.Setting, s.Claims.Cast
	}
	return "request.jwt.claims", "json"
}

// MintClaims builds the claims blob a session presents (the value of the GUC the
// policies read) from a principal's claim values. Every supplied key must be a
// real key of the spec's claims contract — a typo or a stale key is rejected
// rather than silently producing a claim no policy reads. A principal supplies
// only the subset of keys it has (a customer: its customer + scope ids; an admin:
// its subject + scope ids). The JSON is deterministic (sorted keys).
func (s *Spec) MintClaims(values map[string]string) (string, error) {
	contract, err := s.ClaimsContract()
	if err != nil {
		return "", err
	}
	known := make(map[string]bool, len(contract))
	for _, k := range contract {
		known[k] = true
	}
	var bad []string
	for k := range values {
		if !known[k] {
			bad = append(bad, k)
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		return "", fmt.Errorf("MintClaims: key(s) not in the claims contract: %v", bad)
	}
	b, err := json.Marshal(values) // encoding/json sorts map keys → deterministic
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ClaimsSetSQL renders the statement that installs a minted claims blob into the
// session GUC the policies read. The blob binds to $1 (the caller passes the
// MintClaims result); local=true scopes it to the current transaction. Pair this
// with `SET LOCAL ROLE <connection role>` so RLS is in force.
func (s *Spec) ClaimsSetSQL(local bool) string {
	setting, _ := s.claimSetting()
	return fmt.Sprintf("SELECT set_config('%s', $1, %t)", setting, local)
}

// --- (b) verb PDP enforcement -----------------------------------------------

// Decision is the outcome of a PDP authorization check.
type Decision int

const (
	// Allow: the procedure is governed and the caller holds the required permission.
	Allow Decision = iota
	// Deny: the procedure is governed and the caller lacks the required permission.
	Deny
	// NotGoverned: the procedure is not governed by this PDP (explicitly exempt, or
	// absent from the table) — the caller must decide what that means (other layers
	// may still apply); this PDP makes no claim on it.
	NotGoverned
)

func (d Decision) String() string {
	switch d {
	case Allow:
		return "allow"
	case Deny:
		return "deny"
	default:
		return "ungoverned"
	}
}

// Authorize decides whether a caller may invoke a procedure under this PDP. A
// governed procedure (in Policy) is allowed iff `holds` reports the caller has
// the required permission; an exempt or unlisted procedure is Ungoverned. This is
// the enforcement logic every consumer of the emitted PDP map would otherwise
// hand-write (the verb gate RLS can't express).
func (p *PDP) Authorize(procedure string, holds func(perm string) bool) Decision {
	if perm, ok := p.Policy[procedure]; ok {
		if holds(perm) {
			return Allow
		}
		return Deny
	}
	return NotGoverned
}

// --- (c) DB-delegating point-check ------------------------------------------

// PointCheckSQL renders a read point-check for an object: a query that, run UNDER
// a principal's minted claims (ClaimsSetSQL) and the RLS connection role, returns
// whether that principal can SEE a given row — i.e. the row passes the object's
// SELECT policy. $1 binds the row id. The DATABASE decides (the real RLS predicate
// runs); this returns no policy logic of its own. Use it for UI affordances
// ("can this user open this record?"), never as a substitute for enforcement —
// enforcement is the RLS itself.
func (s *Spec) PointCheckSQL(object string) (string, error) {
	for _, o := range s.Objects {
		if o.Name == object {
			return fmt.Sprintf("SELECT EXISTS (SELECT 1 FROM %s WHERE id = $1)", o.Table), nil
		}
	}
	return "", fmt.Errorf("PointCheckSQL: no object %q in the spec", object)
}
