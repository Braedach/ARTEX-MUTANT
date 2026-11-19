package server

import (
	"fmt"
	"path/filepath"
)

// joinWithin joins rel under base and refuses anything that is not a plain local
// path or that resolves outside base (ARTEX-MUTANT hardening, defence in depth).
// The callers already validate names with whitelists (validSkillName, skillRelPath);
// this is the independent containment check at the point of use, so a future change
// to one of those validators cannot silently open a traversal. filepath.IsLocal
// rejects absolute paths, "..", empty paths and reserved names.
func joinWithin(base string, rel ...string) (string, error) {
	r := filepath.Join(rel...)
	// "." is local but names base itself; a delete or overwrite must never target it.
	if r == "." || !filepath.IsLocal(r) {
		return "", fmt.Errorf("unsafe path %q", r)
	}
	full := filepath.Join(base, r)
	within, err := filepath.Rel(base, full)
	if err != nil || within == "." || !filepath.IsLocal(within) {
		return "", fmt.Errorf("path %q escapes %q", r, base)
	}
	return full, nil
}

// skillJoin is joinWithin rooted at the skills directory.
func (s *Server) skillJoin(rel ...string) (string, bool) {
	p, err := joinWithin(s.skillDir, rel...)
	return p, err == nil
}
