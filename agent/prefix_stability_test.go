package agent

import (
	"encoding/json"
	"testing"
	"time"

	actool "github.com/Autumn-27/norma/tool"
)

// Prompt caching (Anthropic's explicit markers and the automatic prefix caches of
// OpenAI-style providers alike) only pays off when the prefix of consecutive calls
// is byte-identical. These tests pin the two things a prefix is made of: the tool
// list (order and text) and the system prompt (no clock, no per-call data).

func toolFingerprint(t *testing.T, tools []actool.CoreTool) string {
	t.Helper()
	type row struct {
		N string         `json:"n"`
		D string         `json:"d"`
		S map[string]any `json:"s"`
	}
	rows := make([]row, 0, len(tools))
	for _, tl := range tools {
		rows = append(rows, row{tl.Name(), tl.Description(), tl.InputSchema()})
	}
	b, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestToolOrderIsStable(t *testing.T) {
	build := map[string]func() []actool.CoreTool{
		"worker": func() []actool.CoreTool {
			return append(NewToolSet(nil, "worker").WorkerTools(), defaultToolsExcept()...)
		},
		"planner": func() []actool.CoreTool {
			return append(NewToolSet(nil, "planner").PlannerTools(), actool.DefaultTools()...)
		},
		"goals": func() []actool.CoreTool {
			ts := NewToolSet(nil, "goals")
			return []actool.CoreTool{ts.setGoals(), ts.setConstraints()}
		},
	}
	for name, fn := range build {
		first := toolFingerprint(t, fn())
		for i := 0; i < 20; i++ {
			if got := toolFingerprint(t, fn()); got != first {
				t.Fatalf("%s: tool list changed between builds (iteration %d); this defeats prompt caching", name, i)
			}
		}
	}
}

func TestSystemPromptHasNoClockOrPerCallData(t *testing.T) {
	// The default prompts must not embed the time: a per-second timestamp in the
	// cached prefix would make every call a cache miss AND pay the write premium.
	a := plannerSystem("goal", "/data", "/work")
	b := chatSystem("assistant", "/data", "/work")
	time.Sleep(1100 * time.Millisecond)
	if a != plannerSystem("goal", "/data", "/work") {
		t.Fatal("planner system prompt changes with time")
	}
	if b != chatSystem("assistant", "/data", "/work") {
		t.Fatal("chat system prompt changes with time")
	}
	if g1, g2 := goalsSystem("/data", true), goalsSystem("/data", true); g1 != g2 {
		t.Fatal("goals system prompt is not deterministic")
	}
	if m1, m2 := mainAgentSystem("g", "/data", "/work"), mainAgentSystem("g", "/data", "/work"); m1 != m2 {
		t.Fatal("main-agent system prompt is not deterministic")
	}
}
