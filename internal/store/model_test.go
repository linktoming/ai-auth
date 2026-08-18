package store

import "testing"

func TestMatchGlob(t *testing.T) {
	cases := []struct {
		pattern, value string
		want           bool
	}{
		{"*", "anything", true},
		{"prod/db", "prod/db", true},
		{"prod/db", "prod/dbx", false},
		{"prod/*", "prod/db", true},
		{"prod/*", "prod/a/b/c", true},
		{"prod/*", "staging/db", false},
		{"*/db", "prod/db", true},
		{"*/db", "prod/db2", false},
		{"prod/*/password", "prod/web/password", true},
		{"prod/*/password", "prod/web/username", false},
		{"", "", true},
		{"", "x", false},
		// A pattern must not match a value shorter than its literal parts.
		{"ab*cd", "abcd", true},
		{"ab*cd", "abc", false},
		{"a*b*c", "axxbyyc", true},
		{"a*b*c", "axxc", false},
	}
	for _, tc := range cases {
		if got := matchGlob(tc.pattern, tc.value); got != tc.want {
			t.Errorf("matchGlob(%q, %q) = %v, want %v", tc.pattern, tc.value, got, tc.want)
		}
	}
}

func TestSeedFieldIsNeverReleasable(t *testing.T) {
	item := &Item{
		Name: "x",
		Fields: map[string]*Field{
			// Even if something managed to set the flag, the name alone must
			// keep the value inside the vault.
			SeedField:  {Releasable: true},
			"password": {Releasable: true},
			"internal": {Releasable: false},
		},
	}
	if item.Releasable(SeedField) {
		t.Fatal("the seed field must never be releasable")
	}
	if !item.Releasable("password") {
		t.Fatal("password should be releasable")
	}
	if item.Releasable("internal") {
		t.Fatal("a non-releasable field must stay non-releasable")
	}
	if item.Releasable("missing") {
		t.Fatal("a missing field must not be releasable")
	}
}

func TestGrantMatching(t *testing.T) {
	g := &Grant{
		Items:          []string{"prod/*"},
		Actions:        []Action{ActionRead},
		AllowedTargets: []string{"*.example.com"},
	}
	if !g.MatchesItem("prod/db") || g.MatchesItem("staging/db") {
		t.Fatal("item matching is wrong")
	}
	if !g.Allows(ActionRead) || g.Allows(ActionTOTP) {
		t.Fatal("action matching is wrong")
	}
	// An empty field list means every releasable field.
	if !g.MatchesField("anything") {
		t.Fatal("an empty field list should allow any field")
	}
	if !g.MatchesTarget("db.example.com") || g.MatchesTarget("db.evil.com") {
		t.Fatal("target matching is wrong")
	}

	// An empty target list places no restriction at all.
	open := &Grant{Items: []string{"*"}}
	if !open.MatchesTarget("anywhere") {
		t.Fatal("an empty target list should allow any target")
	}
}
