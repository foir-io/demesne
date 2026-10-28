package demesne

import (
	"reflect"
	"testing"
)

func TestATextArrayReadsPostgresTextForm(t *testing.T) {
	for _, tc := range []struct {
		src  any
		want TextArray
	}{
		{"{}", TextArray{}},
		{"{a,b}", TextArray{"a", "b"}},
		{[]byte(`{"a b","c,d","e\"f",NULL,"NULL"}`), TextArray{"a b", "c,d", `e"f`, "", "NULL"}},
		{nil, TextArray{}},
		{[]string{"x"}, TextArray{"x"}},
	} {
		var got TextArray
		if err := got.Scan(tc.src); err != nil {
			t.Fatalf("%v: %v", tc.src, err)
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%v: got %q, want %q", tc.src, got, tc.want)
		}
	}
	for _, bad := range []any{"a,b", "{{a},{b}}", `{"a}`, `{"a"b}`, 7} {
		var got TextArray
		if err := got.Scan(bad); err == nil {
			t.Errorf("%v: read as %q", bad, got)
		}
	}
}

func TestMustDecodeRefusesAProjectionThatDoesntFit(t *testing.T) {
	if got := MustDecode[Claims](`{"setting":"s","contract":["a"]}`); got.Setting != "s" || got.Contract[0] != "a" {
		t.Fatalf("got %+v", got)
	}
	defer func() {
		if recover() == nil {
			t.Fatal("a projection that doesn't fit decoded")
		}
	}()
	MustDecode[Claims](`{"setting":"s","novel":true}`)
}
