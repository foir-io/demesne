package demesne

import (
	"fmt"
	"strings"
)

// TextArray scans a Postgres text[] in the text form every driver can return, such as {a,"b c",NULL}. NULL elements
// read as empty strings, and a NULL array as an empty one.
type TextArray []string

// Scan reads src, a string or []byte in Postgres's array text form, or nil.
func (a *TextArray) Scan(src any) error {
	var s string
	switch v := src.(type) {
	case nil:
		*a = TextArray{}
		return nil
	case string:
		s = v
	case []byte:
		s = string(v)
	case []string:
		*a = append(TextArray{}, v...)
		return nil
	default:
		return fmt.Errorf("demesne: a text[] can't be read from %T", src)
	}
	out, err := parseTextArray(s)
	if err != nil {
		return err
	}
	*a = out
	return nil
}

func parseTextArray(s string) (TextArray, error) {
	if len(s) < 2 || s[0] != '{' || s[len(s)-1] != '}' {
		return nil, fmt.Errorf("demesne: %q is not a one-dimensional text[]", s)
	}
	body := s[1 : len(s)-1]
	out := TextArray{}
	if body == "" {
		return out, nil
	}
	for i := 0; i <= len(body); {
		var b strings.Builder
		quoted := i < len(body) && body[i] == '"'
		if quoted {
			i++
			for ; i < len(body) && body[i] != '"'; i++ {
				if body[i] == '\\' && i+1 < len(body) {
					i++
				}
				b.WriteByte(body[i])
			}
			if i >= len(body) {
				return nil, fmt.Errorf("demesne: %q has an unterminated element", s)
			}
			i++
		} else {
			for ; i < len(body) && body[i] != ','; i++ {
				if body[i] == '{' || body[i] == '"' {
					return nil, fmt.Errorf("demesne: %q is not a one-dimensional text[]", s)
				}
				b.WriteByte(body[i])
			}
		}
		elem := b.String()
		if !quoted && strings.EqualFold(elem, "NULL") {
			elem = ""
		}
		out = append(out, elem)
		if i < len(body) && body[i] != ',' {
			return nil, fmt.Errorf("demesne: %q has text after a quoted element", s)
		}
		i++
	}
	return out, nil
}
