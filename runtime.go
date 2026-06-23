package demesne

import (
	"encoding/json"
	"fmt"
	"sort"
)

func (s *Spec) claimSetting() (setting, cast string) {
	if s.Claims != nil {
		return s.Claims.Setting, s.Claims.Cast
	}
	return "request.jwt.claims", "json"
}

func (s *Spec) MintClaims(values map[string]string) (string, error) {
	contract, err := s.ClaimsContract()
	if err != nil {
		return "", err
	}
	return MintClaimsValues(contract, values)
}

func MintClaimsValues(contract []string, values map[string]string) (string, error) {
	return MintClaimsValuesWithExtra(contract, values, nil)
}

func MintClaimsValuesWithExtra(contract []string, values, extra map[string]string) (string, error) {
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
	merged := make(map[string]string, len(values)+len(extra))
	for k, v := range values {
		merged[k] = v
	}
	for k, v := range extra {
		merged[k] = v
	}
	b, err := json.Marshal(merged)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (s *Spec) ClaimsSetSQL(local bool) string {
	setting, _ := s.claimSetting()
	return fmt.Sprintf("SELECT set_config('%s', $1, %t)", setting, local)
}

type Decision int

const (
	Allow Decision = iota

	Deny

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

func (p *PDP) Authorize(procedure string, holds func(perm string) bool) Decision {
	if perm, ok := p.Policy[procedure]; ok {
		if holds(perm) {
			return Allow
		}
		return Deny
	}
	return NotGoverned
}

func CapabilityGateErr(object, verb string) error {
	return fmt.Errorf("%s.%s is a capability (@pdp) verb with no row-level check — resolve held permissions and call Can%s(held) on the %s object", object, verb, goExport(verb), goExport(object))
}

func ComposeCan(pointGoverned, pointAllow bool, pdp Decision) Decision {
	if !pointGoverned && pdp == NotGoverned {
		return NotGoverned
	}
	if pointGoverned && !pointAllow {
		return Deny
	}
	if pdp == Deny {
		return Deny
	}
	return Allow
}

func (s *Spec) PointCheckSQL(object string) (string, error) {
	for _, o := range s.Objects {
		if o.Name == object {
			if !o.pointCheckable() {
				return "", fmt.Errorf("PointCheckSQL: object %q has a composite primary key (%v) — no single-column row identity to point-check", object, o.PKCols)
			}
			return fmt.Sprintf("SELECT EXISTS (SELECT 1 FROM %s WHERE %s = $1)", o.Table, o.pk()), nil
		}
	}
	return "", fmt.Errorf("PointCheckSQL: no object %q in the spec", object)
}
