package server

import (
	"path/filepath"
	"testing"
)

func TestJoinWithin(t *testing.T) {
	base := filepath.Join("data", "skills")
	good := [][]string{{"nmap"}, {"nmap", "SKILL.md"}, {"nmap", "scripts/run.sh"}}
	for _, g := range good {
		if _, err := joinWithin(base, g...); err != nil {
			t.Fatalf("joinWithin(%v) rejected: %v", g, err)
		}
	}
	bad := [][]string{{".."}, {"a", "../.."}, {"/etc/passwd"}, {""}, {"."}, {"a/../../b"}}
	for _, b := range bad {
		if p, err := joinWithin(base, b...); err == nil {
			t.Fatalf("joinWithin(%v) = %q, want error", b, p)
		}
	}
}
