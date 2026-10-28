package demesne

import (
	"encoding/json"
	"fmt"
	"strings"
)

// MustDecode decodes a projection demesne emitted, as JSON, into a T. Generated code calls it once, when its package
// initialises. It panics on JSON that doesn't fit T, a field T lacks included, which only a hand-edited generated file
// or one from a newer demesne can hold.
func MustDecode[T any](projection string) T {
	var out T
	dec := json.NewDecoder(strings.NewReader(projection))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		panic(fmt.Sprintf("demesne: a generated projection doesn't fit %T: %v", out, err))
	}
	return out
}
