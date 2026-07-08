package demesne

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func exampleSpecForDoc() *Spec {
	src, err := os.ReadFile(filepath.Join("examples", "example.demesne"))
	if err != nil {
		panic(err)
	}
	s, err := Parse(string(src))
	if err != nil {
		panic(err)
	}
	return s
}

func ExampleSpec_Vocabularies() {
	s := exampleSpecForDoc()
	for _, v := range s.Vocabularies() {
		fmt.Println(v.Name)
		for _, p := range v.Permissions {
			fmt.Printf("  %s parameterized=%v\n", p.Name, p.Parameterized)
		}
	}
	// Output:
	// staff
	//   docs:read parameterized=false
	//   docs:write parameterized=false
	//   docs:publish parameterized=false
	//   docs:read:* parameterized=true
	// member
	//   self:read parameterized=false
	//   self:write parameterized=false
	// platform
	//   platform:manage parameterized=false
}

func ExampleSpec_ExpandedPresets() {
	s := exampleSpecForDoc()
	presets, err := s.ExpandedPresets("staff")
	if err != nil {
		panic(err)
	}
	names := make([]string, 0, len(presets))
	for name := range presets {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Printf("%s = %s\n", name, strings.Join(presets[name], " "))
	}
	// Output:
	// tenant_owner = docs:publish docs:read docs:read:* docs:write
	// ws_editor = docs:publish docs:read docs:write
	// ws_viewer = docs:read
}
