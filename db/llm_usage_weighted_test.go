package db

import (
	"math"
	"testing"
)

func TestWeightedTokensFormula(t *testing.T) {
	cases := []struct {
		in, out, cr, cw int
		want            float64
	}{
		{1000, 0, 0, 0, 1000},                     // plain uncached input
		{1000, 100, 0, 0, 1000 + 500},             // output costs 5x
		{1000, 0, 900, 0, 100 + 90},               // cache read is a tenth
		{1000, 0, 0, 800, 200 + 1000},             // cache write is 1.25x
		{1000, 10, 600, 300, 100 + 375 + 60 + 50}, // all four
		{100, 0, 900, 0, 0 + 90},                  // inconsistent input: never negative
	}
	for _, c := range cases {
		if got := WeightedTokens(c.in, c.out, c.cr, c.cw); math.Abs(got-c.want) > 1e-9 {
			t.Errorf("WeightedTokens(%d,%d,%d,%d) = %v, want %v", c.in, c.out, c.cr, c.cw, got, c.want)
		}
	}
}

// The Go formula and the SQL formula must agree, or the in-memory running total and
// the persisted total the guard reloads after a restart would disagree.
func TestTaskWeightedTokensMatchesGoFormula(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer d.Close()
	if err := d.EnsureLLMUsageTable(); err != nil {
		t.Fatal(err)
	}
	const task = "zz_test_weighted_tokens"
	cleanup := func() { _, _ = d.Exec(`DELETE FROM llm_usage WHERE task_id = $1`, task) }
	cleanup()
	defer cleanup()

	calls := []LLMUsage{
		{InputTokens: 30000, OutputTokens: 300},
		{InputTokens: 31000, OutputTokens: 200, CacheRead: 29000},
		{InputTokens: 32000, OutputTokens: 100, CacheRead: 20000, CacheWrite: 9000},
		{InputTokens: 500, OutputTokens: 5, CacheRead: 900}, // inconsistent: clamps at 0 uncached
	}
	var want float64
	for _, c := range calls {
		c.TaskID, c.Worker, c.Model, c.Status = task, "worker", "m", "ok"
		if err := d.InsertLLMUsage(&c); err != nil {
			t.Fatal(err)
		}
		want += WeightedTokens(c.InputTokens, c.OutputTokens, c.CacheRead, c.CacheWrite)
	}
	got, err := d.TaskWeightedTokens(task)
	if err != nil {
		t.Fatal(err)
	}
	if math.Abs(got-want) > 1e-6 {
		t.Fatalf("SQL total %v != Go total %v", got, want)
	}
	if none, err := d.TaskWeightedTokens("zz_no_such_task"); err != nil || none != 0 {
		t.Fatalf("unknown task: want 0,nil got %v,%v", none, err)
	}
}
