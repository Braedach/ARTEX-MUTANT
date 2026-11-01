package intercept

import (
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestRuleMatchesDecodesJSONEscapes(t *testing.T) {
	// G-03: "read" is the JSON-escaped form of "read" - a byte-for-byte
	// match against the raw request body never sees the word "read" at all.
	input := []byte(`{"command":"read /app/jwt.key"}`)

	r := compiledRule{InterceptRule: db.InterceptRule{
		MatchTarget: "tool_input",
		MatchType:   "substring",
		Pattern:     "read",
	}}
	if !ruleMatches(r, "Bash", input, "") {
		t.Fatal("expected the decoded-form fallback to catch a JSON-escaped pattern")
	}
}

func TestRuleMatchesStillMatchesPlainInput(t *testing.T) {
	input := []byte(`{"command":"read /app/jwt.key"}`)
	r := compiledRule{InterceptRule: db.InterceptRule{
		MatchTarget: "tool_input",
		MatchType:   "substring",
		Pattern:     "read",
	}}
	if !ruleMatches(r, "Bash", input, "") {
		t.Fatal("expected a plain, unescaped match to still work")
	}
}

func TestRuleMatchesNoFalsePositiveFromDecoding(t *testing.T) {
	input := []byte(`{"command":"list files"}`)
	r := compiledRule{InterceptRule: db.InterceptRule{
		MatchTarget: "tool_input",
		MatchType:   "substring",
		Pattern:     "read",
	}}
	if ruleMatches(r, "Bash", input, "") {
		t.Fatal("unrelated input must not match")
	}
}

func TestRuleMatchesNonJSONInputFallsBackToRawOnly(t *testing.T) {
	// decodedToolInput returns "" for non-JSON input; must not panic and must
	// still try the raw-bytes match.
	input := []byte("not json at all, just read this")
	r := compiledRule{InterceptRule: db.InterceptRule{
		MatchTarget: "tool_input",
		MatchType:   "substring",
		Pattern:     "read",
	}}
	if !ruleMatches(r, "Bash", input, "") {
		t.Fatal("expected raw-bytes match to still apply to non-JSON input")
	}
}

func TestDecodedToolInputInvalidJSON(t *testing.T) {
	if got := decodedToolInput([]byte("{not json")); got != "" {
		t.Fatalf("expected empty string for invalid JSON, got %q", got)
	}
}
