package pathguard

import (
	"os"
	"path/filepath"
	"testing"
)

func call(t *testing.T, tool, key, path, wd string) error {
	t.Helper()
	b := []byte(`{"` + key + `":"` + path + `"}`)
	return Check(tool, b, wd)
}

func setup(t *testing.T) (dir, key string) {
	t.Helper()
	Reset()
	t.Cleanup(Reset)
	dir = t.TempDir()
	if r, err := filepath.EvalSymlinks(dir); err == nil {
		dir = r
	}
	key = filepath.Join(dir, "keys", "jwt.key")
	if err := os.MkdirAll(filepath.Dir(key), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	Protect(key, filepath.Join(dir, "data", "traffic", "_ca"))
	return dir, key
}

func TestDirectAccessDenied(t *testing.T) {
	_, key := setup(t)
	for _, tool := range []string{"Read", "Write", "Edit", "MultiEdit"} {
		if call(t, tool, "file_path", key, "") == nil {
			t.Fatalf("%s of the key was allowed", tool)
		}
	}
	if call(t, "Grep", "path", key, "") == nil {
		t.Fatal("Grep of the key was allowed")
	}
}

func TestSymlinkIntoWorkspaceDenied(t *testing.T) {
	dir, key := setup(t)
	ws := filepath.Join(dir, "ws")
	_ = os.MkdirAll(ws, 0o755)
	if err := os.Symlink(key, filepath.Join(ws, "x")); err != nil {
		t.Fatal(err)
	}
	if call(t, "Read", "file_path", filepath.Join(ws, "x"), "") == nil {
		t.Fatal("a symlink in the workspace to the key was readable")
	}
	// Relative spelling resolved against the working directory.
	if call(t, "Read", "file_path", "x", ws) == nil {
		t.Fatal("relative path to the symlink was readable")
	}
}

func TestRelativeTraversalDenied(t *testing.T) {
	dir, _ := setup(t)
	ws := filepath.Join(dir, "ws", "task")
	_ = os.MkdirAll(ws, 0o755)
	if call(t, "Read", "file_path", "../../keys/jwt.key", ws) == nil {
		t.Fatal("relative traversal to the key was readable")
	}
}

func TestNewFileUnderProtectedDirDenied(t *testing.T) {
	dir, _ := setup(t)
	ca := filepath.Join(dir, "data", "traffic", "_ca")
	if call(t, "Write", "file_path", filepath.Join(ca, "evil.pem"), "") == nil {
		t.Fatal("writing a new file under the CA directory was allowed")
	}
}

func TestSymlinkedParentOfNewFileDenied(t *testing.T) {
	dir, _ := setup(t)
	ca := filepath.Join(dir, "data", "traffic", "_ca")
	_ = os.MkdirAll(ca, 0o700)
	ws := filepath.Join(dir, "ws")
	_ = os.MkdirAll(ws, 0o755)
	if err := os.Symlink(ca, filepath.Join(ws, "lnk")); err != nil {
		t.Fatal(err)
	}
	if call(t, "Write", "file_path", filepath.Join(ws, "lnk", "new.pem"), "") == nil {
		t.Fatal("writing through a symlinked parent into the CA directory was allowed")
	}
}

func TestGrepOverAncestorDeniedButListingAllowed(t *testing.T) {
	dir, _ := setup(t)
	if call(t, "Grep", "path", dir, "") == nil {
		t.Fatal("Grep over a directory containing the key was allowed")
	}
	if err := call(t, "LS", "path", dir, ""); err != nil {
		t.Fatalf("LS of an ancestor should be allowed: %v", err)
	}
	if err := call(t, "Glob", "path", dir, ""); err != nil {
		t.Fatalf("Glob of an ancestor should be allowed: %v", err)
	}
}

func TestProcAndRunSecretsDenied(t *testing.T) {
	setup(t)
	for _, p := range []string{"/proc/self/environ", "/proc/1/environ", "/proc/self/cmdline", "/proc/self/task/1/environ", "/run/secrets/db", "/run/secrets"} {
		if call(t, "Read", "file_path", p, "") == nil {
			t.Fatalf("%s was readable", p)
		}
	}
}

func TestOrdinaryWorkAllowed(t *testing.T) {
	dir, _ := setup(t)
	ws := filepath.Join(dir, "ws")
	_ = os.MkdirAll(ws, 0o755)
	_ = os.WriteFile(filepath.Join(ws, "notes.txt"), []byte("x"), 0o644)
	for _, tool := range []string{"Read", "Write", "Edit"} {
		if err := call(t, tool, "file_path", filepath.Join(ws, "notes.txt"), ""); err != nil {
			t.Fatalf("%s of an ordinary workspace file was denied: %v", tool, err)
		}
	}
	if err := call(t, "Grep", "path", ws, ""); err != nil {
		t.Fatalf("Grep of the workspace was denied: %v", err)
	}
	if err := call(t, "Read", "file_path", "/etc/hostname", ""); err != nil {
		t.Fatalf("Read of /etc/hostname was denied: %v", err)
	}
	if err := Check("Bash", []byte(`{"command":"cat /proc/self/environ"}`), ""); err != nil {
		t.Fatalf("Bash is out of scope for this guard: %v", err)
	}
	if err := Check("Read", []byte(`{not json`), ""); err != nil {
		t.Fatalf("malformed input must be left to the tool: %v", err)
	}
}
