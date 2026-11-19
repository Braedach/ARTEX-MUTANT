package traffic

import (
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
