package traffic

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A recorded host must never map onto the traffic directory itself or its parent.
func TestSanitizeNeverYieldsDotNames(t *testing.T) {
	base := filepath.Join("data", "traffic")
	for _, h := range []string{".", "..", "../..", "a/../..", "..\\..", "", "_"} {
		got := sanitize(h)
		if got == "." || got == ".." {
			t.Fatalf("sanitize(%q) = %q", h, got)
		}
		joined := filepath.Join(base, got)
		rel, err := filepath.Rel(base, joined)
		if err != nil || !filepath.IsLocal(rel) || strings.Contains(rel, string(filepath.Separator)) {
			t.Fatalf("sanitize(%q) = %q escapes or equals the traffic dir (%q)", h, got, joined)
		}
	}
	if sanitize("example.com:8443") != "example.com_8443" {
		t.Fatal("ordinary hosts must keep their existing directory names")
	}
}

// A recorded host must never map onto an internal directory or anything outside the
// traffic directory, because host deletion moves and removes these directories.
func TestHostDirRefusesInternalAndEscapingNames(t *testing.T) {
	tr := &Traffic{dir: t.TempDir()}
	for _, h := range []string{"_blobs", "_ca", "_index", "_delete_staging", ".", "..", "_anything"} {
		if d, ok := tr.hostDir(h); ok {
			// (kept for safety if a name ever sanitises to "root")
			if sanitize(h) == "root" {
				continue
			}
			t.Fatalf("hostDir(%q) = %q, want refused", h, d)
		}
	}
	for _, h := range []string{"example.com", "example.com:8443", "10.0.0.5", "a.b-c.example", "../.."} {
		d, ok := tr.hostDir(h)
		if !ok || filepath.Dir(d) != tr.dir {
			t.Fatalf("hostDir(%q) = %q, %v; want a direct child of the traffic dir", h, d, ok)
		}
	}
}

func TestStageTreesRefusesPathsOutsideTrafficDir(t *testing.T) {
	root := t.TempDir()
	tr := &Traffic{dir: filepath.Join(root, "traffic")}
	if err := os.MkdirAll(filepath.Join(tr.dir, "example.com"), 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(root, "precious")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{outside, tr.dir, filepath.Join(tr.dir, "_blobs"), filepath.Join(tr.dir, "..", "precious")} {
		if _, _, err := tr.stageTrees([]string{bad}); err == nil {
			t.Fatalf("stageTrees accepted %q", bad)
		}
		if _, err := os.Stat(outside); err != nil {
			t.Fatalf("%q was moved: %v", outside, err)
		}
	}
}
