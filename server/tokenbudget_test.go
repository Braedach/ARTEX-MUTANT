package server

import (
	"errors"
	"testing"
)

func TestBudgetTrackerLoadsOnceThenAccumulates(t *testing.T) {
	b := newBudgetTracker()
	loads := 0
	load := func() (float64, error) { loads++; return 1000, nil }
	if got := b.add("7", 50, load); got != 1000 {
		t.Fatalf("first call returns the persisted total (it already contains this call): got %v", got)
	}
	if got := b.add("7", 50, load); got != 1050 {
		t.Fatalf("later calls add: got %v", got)
	}
	if got := b.add("7", 25, load); got != 1075 {
		t.Fatalf("got %v", got)
	}
	if loads != 1 {
		t.Fatalf("the ledger must be read once per task, got %d reads", loads)
	}
	if got := b.add("8", 10, func() (float64, error) { return 10, nil }); got != 10 {
		t.Fatalf("tasks are tracked separately: got %v", got)
	}
}

func TestBudgetTrackerSurvivesLedgerError(t *testing.T) {
	b := newBudgetTracker()
	got := b.add("9", 400, func() (float64, error) { return 0, errors.New("db down") })
	if got != 400 {
		t.Fatalf("on a ledger error the guard must still count what it has seen, got %v", got)
	}
	if got := b.add("9", 100, func() (float64, error) { return 0, errors.New("db down") }); got != 500 {
		t.Fatalf("got %v", got)
	}
}

func TestBudgetTrackerForget(t *testing.T) {
	b := newBudgetTracker()
	b.add("3", 5, func() (float64, error) { return 5, nil })
	b.forget("3")
	if got := b.add("3", 1, func() (float64, error) { return 77, nil }); got != 77 {
		t.Fatalf("after forget the total is reloaded, got %v", got)
	}
}

func TestHumanTokens(t *testing.T) {
	for in, want := range map[float64]string{12: "12", 1500: "1.5k", 25_000_000: "25.0M", 2.5e9: "2.5B"} {
		if got := humanTokens(in); got != want {
			t.Errorf("humanTokens(%v) = %q, want %q", in, got, want)
		}
	}
}
