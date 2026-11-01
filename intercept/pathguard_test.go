package intercept

import (
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestResolvedPathFormRewritesRelativeTraversal(t *testing.T) {
	got := resolvedPathForm(`cat ../../etc/passwd`, "/data/task/42/sub")
	want := `cat /data/task/etc/passwd`
	if got != want {
		t.Fatalf("resolvedPathForm() = %q, want %q", got, want)
	}
}

func TestResolvedPathFormNormalizesAbsoluteWithoutReRooting(t *testing.T) {
	got := resolvedPathForm(`cat /data/task/42/../../etc/shadow`, "/data/task/42")
	want := `cat /data/etc/shadow`
	if got != want {
		t.Fatalf("resolvedPathForm() = %q, want %q", got, want)
	}
}

func TestResolvedPathFormEmptyWhenNoWorkingDir(t *testing.T) {
	if got := resolvedPathForm(`cat ../../etc/passwd`, ""); got != "" {
		t.Fatalf("resolvedPathForm() = %q, want empty (no working dir supplied)", got)
	}
}

func TestResolvedPathFormEmptyWhenNothingChanged(t *testing.T) {
	// A plain command with no path-like token at all: no candidate worth adding.
	if got := resolvedPathForm(`whoami`, "/data/task/42"); got != "" {
		t.Fatalf("resolvedPathForm() = %q, want empty (nothing to resolve)", got)
	}
	// An already-clean absolute path resolves to itself - still nothing new.
	if got := resolvedPathForm(`cat /etc/hostname`, "/data/task/42"); got != "" {
		t.Fatalf("resolvedPathForm() = %q, want empty (already clean)", got)
	}
}

// TestRuleMatchesCatchesTraversalOnlyVisibleAfterResolution is the end-to-end
// case reArtex's analysis describes: a rule written to catch a sensitive
// absolute path never sees that path in the literal tool input - it only
// appears once the relative traversal is resolved against the call's real
// working directory.
func TestRuleMatchesCatchesTraversalOnlyVisibleAfterResolution(t *testing.T) {
	input := []byte(`{"command":"cat ../../../../etc/passwd"}`)
	// Note the leading space baked into the pattern: "cat ../../../../etc/passwd"
	// already contains the bare substring "/etc/passwd" by accident (it's a
	// suffix of the relative path), which would make this test pass for the
	// wrong reason. "cat /etc/passwd" only appears once the "../" segments
	// are actually resolved away.
	r := compiledRule{InterceptRule: db.InterceptRule{
		MatchTarget: "tool_input", MatchType: "string", Pattern: "cat /etc/passwd",
	}}
	if ruleMatches(r, "Bash", input, "") {
		t.Fatal("without a working directory, the literal text never contains 'cat /etc/passwd' - this must not match")
	}
	if !ruleMatches(r, "Bash", input, "/home/artex/tasks/42") {
		t.Fatal("expected the resolved form (/etc/passwd) to match once a working directory is supplied")
	}
}

func TestRuleMatchesUnaffectedWhenTraversalStaysInsideWorkingDir(t *testing.T) {
	input := []byte(`{"command":"cat ../sibling/notes.txt"}`)
	r := compiledRule{InterceptRule: db.InterceptRule{
		MatchTarget: "tool_input", MatchType: "string", Pattern: "/etc/passwd",
	}}
	if ruleMatches(r, "Bash", input, "/home/artex/tasks/42/sub") {
		t.Fatal("a traversal that resolves somewhere unrelated to the rule's pattern must not match")
	}
}
