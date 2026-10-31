package server

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWithinRealRootPlainPath(t *testing.T) {
	root := t.TempDir()
	abs := filepath.Join(root, "a", "b.txt")
	if !withinRealRoot(root, abs) {
		t.Fatal("an ordinary path under root, existing or not, must pass")
	}
}

func TestWithinRealRootRejectsSymlinkEscape(t *testing.T) {
	// G-07: a symlink planted INSIDE the work dir that points OUTSIDE it. Every
	// path string involved is lexically under root - only resolving the real
	// target catches this.
	root := t.TempDir()
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secret, []byte("nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	abs := filepath.Join(link, "secret.txt") // lexically "<root>/escape/secret.txt"
	if withinRealRoot(root, abs) {
		t.Fatal("a path through a symlink pointing outside root must be rejected")
	}
}

func TestWithinRealRootAllowsSymlinkStayingInside(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "real"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "alias")
	if err := os.Symlink(filepath.Join(root, "real"), link); err != nil {
		t.Fatal(err)
	}
	abs := filepath.Join(link, "x.txt") // resolves to <root>/real/x.txt - still inside
	if !withinRealRoot(root, abs) {
		t.Fatal("a symlink that stays inside root must be allowed")
	}
}

func TestWsResolveRejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	s := &Server{m: &Manager{dir: root}}
	if _, ok := s.wsResolve("escape/secret.txt"); ok {
		t.Fatal("wsResolve must reject a path that resolves outside the work dir via a symlink")
	}
	// Sanity check: an ordinary path is still accepted.
	if abs, ok := s.wsResolve("plain/file.txt"); !ok || abs != filepath.Join(root, "plain", "file.txt") {
		t.Fatalf("wsResolve rejected an ordinary in-root path: abs=%q ok=%v", abs, ok)
	}
}
