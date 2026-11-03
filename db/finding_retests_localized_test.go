package db

import (
	"testing"
	"unicode"
)

// assertRetestReasonEnglish asserts a retest-reason constant has no leftover
// CJK Han ideograph or Hangul syllable (F9). These constants are concatenated
// directly into FinishFindingRetest/RecoverFindingRetests' SQL literals, so
// pinning the constant also protects the user-facing panel text.
func assertRetestReasonEnglish(t *testing.T, name, s string) {
	t.Helper()
	if s == "" {
		t.Fatalf("%s: empty string", name)
	}
	for _, r := range s {
		if unicode.Is(unicode.Han, r) {
			t.Fatalf("%s: still has a CJK Han ideograph: %q", name, s)
		}
		if unicode.Is(unicode.Hangul, r) {
			t.Fatalf("%s: still has a Hangul syllable: %q", name, s)
		}
	}
}

// TestFindingRetestReasonsLocalized asserts the two terminal-reason constants
// stored in the finding_retests.error column and surfaced as the retest panel
// (finding-retest-panel)'s item.error are in English. Same column/panel as
// server/conversations.go's sibling reasons (convRetest*), so if only one side
// were English, the panel would mix languages.
func TestFindingRetestReasonsLocalized(t *testing.T) {
	assertRetestReasonEnglish(t, "retestNoConclusionReason", retestNoConclusionReason)
	assertRetestReasonEnglish(t, "retestServiceRestartReason", retestServiceRestartReason)
}
