package main

import (
	"reflect"
	"testing"
)

// Go's flag package stops parsing at the first positional argument, so a user
// typing the domain before the flags would previously get "expected exactly
// one domain argument". These cover both orders and the awkward cases.
func TestReorderArgs(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "flags already first are unchanged",
			in:   []string{"--json", "example.com"},
			want: []string{"--json", "example.com"},
		},
		{
			name: "trailing boolean flag is moved ahead of the domain",
			in:   []string{"example.com", "--json"},
			want: []string{"--json", "example.com"},
		},
		{
			name: "trailing valued flag keeps its value attached",
			in:   []string{"example.com", "--types", "A,NS"},
			want: []string{"--types", "A,NS", "example.com"},
		},
		{
			name: "equals form needs no value lookahead",
			in:   []string{"example.com", "--types=A,NS"},
			want: []string{"--types=A,NS", "example.com"},
		},
		{
			name: "mixed order is normalised",
			in:   []string{"--types", "A", "example.com", "--json"},
			want: []string{"--types", "A", "--json", "example.com"},
		},
		{
			name: "a boolean flag does not swallow the domain",
			in:   []string{"--json", "example.com", "--only-resolvers"},
			want: []string{"--json", "--only-resolvers", "example.com"},
		},
		{
			name: "double dash keeps the rest positional",
			in:   []string{"--json", "--", "-weird.example.com"},
			want: []string{"--json", "-weird.example.com"},
		},
		{
			name: "no arguments at all",
			in:   []string{},
			want: []string{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := reorderArgs(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("reorderArgs(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
