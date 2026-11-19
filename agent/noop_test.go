package agent

import (
	"errors"
	"testing"

	"github.com/Autumn-27/norma/harness"
)

func TestIsUnproductiveNoop(t *testing.T) {
	boom := errors.New("x")
	cases := []struct {
		name   string
		reason harness.TerminalReason
		err    error
		tools  int
		text   string
		want   bool
	}{
		{"thinking only", harness.ReasonCompleted, nil, 0, "", true},
		{"whitespace text", harness.ReasonCompleted, nil, 0, " \n\t", true},
		{"called a tool", harness.ReasonCompleted, nil, 1, "", false},
		{"left text", harness.ReasonCompleted, nil, 0, "done: nothing found", false},
		{"errored", harness.ReasonCompleted, boom, 0, "", false},
		{"max turns", harness.ReasonMaxTurns, nil, 0, "", false},
		{"timeout", harness.ReasonTimeout, nil, 0, "", false},
	}
	for _, c := range cases {
		if got := isUnproductiveNoop(c.reason, c.err, c.tools, c.text); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestUnproductiveNoopHasHint(t *testing.T) {
	if reasonHint[ReasonUnproductiveNoop] == "" {
		t.Fatal("ReasonUnproductiveNoop needs a hint for the planner")
	}
}
