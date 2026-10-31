package intercept

import "testing"

// TestDefaultJudgeFailActionIsDeny guards the ARTEX-MUTANT hardening change
// directly: once an operator has enabled the judge, a model error or an
// unparseable reply must fail CLOSED unless they've explicitly chosen
// otherwise. A future edit that quietly flips this back to "allow" (e.g. a
// bad merge from upstream) breaks this test instead of silently reopening
// the gap.
func TestDefaultJudgeFailActionIsDeny(t *testing.T) {
	if defaultJudgeFailAction != "deny" {
		t.Fatalf("defaultJudgeFailAction = %q, want %q", defaultJudgeFailAction, "deny")
	}
}
