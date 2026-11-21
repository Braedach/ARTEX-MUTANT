package server

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/llm"
)

// Per-task token budget.
//
// An agent loop has no natural stopping point other than the model deciding it is
// done, and a task keeps waking its planner and workers for as long as there is
// anything left to try. Prompt caching cuts the price of every turn, but it does
// not cap how many turns happen. The budget is the backstop: when a task has used
// more than the budget, it is paused, with a clear line in the server log, and
// stays paused until the owner raises the budget and resumes it.
//
// The budget is measured in cost-weighted input-token units (db.WeightedTokens),
// not raw tokens, so that a million cached tokens counts as the small fraction of
// a million uncached tokens that it costs. 0 means no limit.

const settingTaskTokenBudget = "task_token_budget"

// defaultTaskTokenBudget is the budget a fresh install starts with: about 25
// million input-token equivalents per task. That is far beyond what a focused scan
// needs once caching is working, and well short of a runaway.
const defaultTaskTokenBudget int64 = 25_000_000

// maxTaskTokenBudget bounds what the setting accepts (a typo guard, not a policy).
const maxTaskTokenBudget int64 = 1_000_000_000_000

// TaskTokenBudget returns the per-task budget in cost-weighted token units.
// 0 = unlimited. An unset or unreadable setting returns the default.
func (m *Manager) TaskTokenBudget() int64 {
	v, ok, err := m.pg.GetSetting(settingTaskTokenBudget)
	if err != nil || !ok {
		return defaultTaskTokenBudget
	}
	n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if err != nil || n < 0 {
		return defaultTaskTokenBudget
	}
	return n
}

// SetTaskTokenBudget persists the per-task budget. 0 disables it.
func (m *Manager) SetTaskTokenBudget(n int64) error {
	if n < 0 || n > maxTaskTokenBudget {
		return fmt.Errorf("task_token_budget must be between 0 and %d", maxTaskTokenBudget)
	}
	return m.pg.SetSetting(settingTaskTokenBudget, strconv.FormatInt(n, 10))
}

// budgetTracker keeps a running cost-weighted total per task so the guard does not
// query the ledger on every call. The first call for a task loads the persisted
// total (which already includes that call's own row); later calls add to it.
type budgetTracker struct {
	mu     sync.Mutex
	totals map[string]float64
}

func newBudgetTracker() *budgetTracker { return &budgetTracker{totals: map[string]float64{}} }

// add records one call and returns the task's running total.
func (b *budgetTracker) add(taskID string, w float64, load func() (float64, error)) float64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	cur, seen := b.totals[taskID]
	if !seen {
		v, err := load()
		if err != nil {
			// Cannot read the ledger: count what this process has seen rather than
			// letting a database hiccup disable the guard.
			v = w
		}
		cur = v
	} else {
		cur += w
	}
	b.totals[taskID] = cur
	return cur
}

// forget drops a task's running total (task deleted).
func (b *budgetTracker) forget(taskID string) {
	b.mu.Lock()
	delete(b.totals, taskID)
	b.mu.Unlock()
}

// onLLMUsage is the llmrec usage hook: it enforces the per-task budget.
func (s *Server) onLLMUsage(taskID string, u llm.Usage) {
	if s.budget == nil {
		return
	}
	w := db.WeightedTokens(u.InputTokens, u.OutputTokens, u.CacheReadTokens, u.CacheWriteTokens)
	total := s.budget.add(taskID, w, func() (float64, error) { return s.m.pg.TaskWeightedTokens(taskID) })
	limit := s.m.TaskTokenBudget()
	if limit <= 0 || total < float64(limit) {
		return
	}
	t, ok := s.m.Task(taskID)
	if !ok || t.lifecycleSnapshot().Paused {
		return
	}
	// Pausing cancels the very calls that are reporting in, so never do it on
	// their goroutine.
	go func() {
		if _, err := s.applyTaskControl(t, "pause"); err != nil {
			log.Printf("[budget] task %s is over its token budget but could not be paused: %v", taskID, err)
			return
		}
		log.Printf("[budget] task %s paused: it has used %s of its %s token budget (cost-weighted units). "+
			"Raise the budget in System settings, then resume the task.",
			taskID, humanTokens(total), humanTokens(float64(limit)))
	}()
}

// humanTokens renders 1234567 as "1.2M".
func humanTokens(v float64) string {
	switch {
	case v >= 1e9:
		return fmt.Sprintf("%.1fB", v/1e9)
	case v >= 1e6:
		return fmt.Sprintf("%.1fM", v/1e6)
	case v >= 1e3:
		return fmt.Sprintf("%.1fk", v/1e3)
	}
	return fmt.Sprintf("%.0f", v)
}
