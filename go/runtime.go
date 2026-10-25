package demesne

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

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

func goExport(s string) string {
	parts := strings.FieldsFunc(s, func(r rune) bool { return r == '_' || r == '-' || r == ':' || r == '.' })
	for i, p := range parts {
		if p == "" {
			continue
		}
		if up := strings.ToUpper(p); commonInitialisms[up] {
			parts[i] = up
			continue
		}
		parts[i] = strings.ToUpper(p[:1]) + p[1:]
	}
	return strings.Join(parts, "")
}

var commonInitialisms = map[string]bool{"ID": true, "URL": true, "API": true, "SQL": true, "UID": true, "ACL": true, "PK": true}
