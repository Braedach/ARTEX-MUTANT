package intercept

import "testing"

// TestFatigueGuardDeniesAfterThreshold verifies the ask-fatigue guard allows
// up to maxAsksPerFatigueWindow identical requests through (so a reviewer
// genuinely dealing with repeated prompts isn't blocked), then auto-denies
// every further request for the same key within the window.
func TestFatigueGuardDeniesAfterThreshold(t *testing.T) {
	g := newFatigueGuard()
	key := "agent-1|Bash|abc123"
	for n := 1; n <= maxAsksPerFatigueWindow; n++ {
		if g.check(key) {
			t.Fatalf("request %d: expected not exceeded (threshold is %d)", n, maxAsksPerFatigueWindow)
		}
	}
	if !g.check(key) {
		t.Fatalf("request %d: expected exceeded", maxAsksPerFatigueWindow+1)
	}
	// A second over-threshold request stays denied too, not just the first.
	if !g.check(key) {
		t.Fatalf("request %d: expected exceeded", maxAsksPerFatigueWindow+2)
	}
}

// TestFatigueGuardScopesByKey verifies the guard tracks each (agent, tool,
// input) triple independently - a different key never inherits another
// key's count, so asking about a genuinely different call is never throttled
// by an unrelated one.
func TestFatigueGuardScopesByKey(t *testing.T) {
	g := newFatigueGuard()
	for n := 0; n < maxAsksPerFatigueWindow+3; n++ {
		g.check("agent-1|Bash|same-call")
	}
	if g.check("agent-1|Bash|different-call") {
		t.Fatal("a different key must not be affected by another key's count")
	}
	if g.check("agent-2|Bash|same-call") {
		t.Fatal("a different agent must not be affected by another agent's count")
	}
}

// TestFatigueGuardResetsAfterWindow verifies entries older than the window
// are treated as a fresh start rather than accumulating forever, by reaching
// into the entry directly and backdating it (avoiding a real sleep).
func TestFatigueGuardResetsAfterWindow(t *testing.T) {
	g := newFatigueGuard()
	key := "agent-1|Bash|abc123"
	for n := 0; n < maxAsksPerFatigueWindow+2; n++ {
		g.check(key)
	}
	g.mu.Lock()
	g.entries[key].windowEnd = g.entries[key].windowEnd.Add(-2 * askFatigueWindow)
	g.mu.Unlock()
	if g.check(key) {
		t.Fatal("expected the first request in a new window to not be exceeded")
	}
}

// TestDefaultAskTimeoutMatchesJudgeDefault documents the deliberate choice to
// reuse the judge's own ask-timeout default (see defaultAskTimeoutSeconds's
// comment) rather than introduce a second magic number for the same
// fail-closed behavior.
func TestDefaultAskTimeoutMatchesJudgeDefault(t *testing.T) {
	if defaultAskTimeoutSeconds != defaultJudgeAskTimeoutSecs {
		t.Fatalf("defaultAskTimeoutSeconds = %d, want %d (defaultJudgeAskTimeoutSecs)", defaultAskTimeoutSeconds, defaultJudgeAskTimeoutSecs)
	}
	if defaultAskTimeoutAction != "deny" {
		t.Fatalf("defaultAskTimeoutAction = %q, want %q", defaultAskTimeoutAction, "deny")
	}
}
