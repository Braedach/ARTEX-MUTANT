package server

import (
	"errors"
	"testing"

	"github.com/Autumn-27/artex/llmpool"
)

// TestRecordLLMTestResult verifies the health-registry wiring described on
// recordLLMTestResult's own comment: a manual connection test's outcome for
// an existing saved profile actually changes what the LLM page's "Healthy"
// badge shows, the same way a real production call would.
func TestRecordLLMTestResult(t *testing.T) {
	const profileID int64 = 42

	t.Run("no profile id - ad hoc test, nothing recorded", func(t *testing.T) {
		health := llmpool.NewRegistry(nil, nil)
		recordLLMTestResult(health, nil, errors.New("anthropic: status 401: invalid x-api-key"))
		if health.IsOpen(profileID) {
			t.Fatal("an ad-hoc test (no profile id) must not record anything")
		}
	})

	t.Run("hard failure trips the breaker immediately", func(t *testing.T) {
		health := llmpool.NewRegistry(nil, nil)
		recordLLMTestResult(health, &[]int64{profileID}[0], errors.New("anthropic: status 401: invalid x-api-key"))
		if !health.IsOpen(profileID) {
			t.Fatal("a hard failure (401) must trip the breaker on the first test")
		}
	})

	t.Run("success clears a previously tripped profile", func(t *testing.T) {
		health := llmpool.NewRegistry(nil, nil)
		id := profileID
		recordLLMTestResult(health, &id, errors.New("anthropic: status 401: invalid x-api-key"))
		if !health.IsOpen(id) {
			t.Fatal("setup: expected the breaker to be open after the failing test")
		}
		recordLLMTestResult(health, &id, nil)
		if health.IsOpen(id) {
			t.Fatal("a successful test must clear the tripped state, same as a real successful call would")
		}
	})

	t.Run("soft failure does not trip on the first occurrence", func(t *testing.T) {
		health := llmpool.NewRegistry(nil, nil)
		id := profileID
		recordLLMTestResult(health, &id, errors.New("connection reset by peer"))
		if health.IsOpen(id) {
			t.Fatal("a single transient (non-hard) failure must not trip the breaker immediately")
		}
	})
}

// The status list drives the "轮询顺序" strip in the UI, so it has to match the
// order PoolProfiles actually runs: active first, then priority DESC, then id ASC
// (input arrives id-ordered, so equal priorities must keep their relative order).
func TestSortPoolStatusMatchesChainOrder(t *testing.T) {
	in := []LLMPoolMemberStatus{
		{ProfileID: "1", Name: "low", Priority: 0},
		{ProfileID: "2", Name: "active", Priority: 0, Active: true},
		{ProfileID: "3", Name: "high", Priority: 10},
		{ProfileID: "4", Name: "mid-a", Priority: 5},
		{ProfileID: "5", Name: "mid-b", Priority: 5},
	}
	sortPoolStatus(in)

	want := []string{"active", "high", "mid-a", "mid-b", "low"}
	for i, w := range want {
		if in[i].Name != w {
			got := make([]string, len(in))
			for j, m := range in {
				got[j] = m.Name
			}
			t.Fatalf("order = %v, want %v", got, want)
		}
	}
}

// The active profile heads the chain no matter how low its own priority is —
// that's the documented precedence, and the UI must not imply otherwise.
func TestActiveProfileHeadsStatusList(t *testing.T) {
	in := []LLMPoolMemberStatus{
		{ProfileID: "1", Name: "loud", Priority: 999},
		{ProfileID: "2", Name: "active", Priority: -5, Active: true},
	}
	sortPoolStatus(in)
	if in[0].Name != "active" {
		t.Fatalf("head = %q, want the active profile regardless of priority", in[0].Name)
	}
}
