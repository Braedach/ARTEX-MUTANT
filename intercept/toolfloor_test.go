package intercept

import (
	"testing"

	"github.com/Autumn-27/artex/db"
)

// TestMandatoryInterceptedToolsCannotBeDisabled verifies the floor documented
// on mandatoryInterceptedTools: IsToolEnabled must keep reading true for a
// mandatory tool even after SetEnabledTools persists a list that omits it
// (or a settings load failure leaves i.enabledTools nil entirely) - a
// settings write alone cannot turn off scrutiny for these tools.
func TestMandatoryInterceptedToolsCannotBeDisabled(t *testing.T) {
	for name := range mandatoryInterceptedTools {
		t.Run(name, func(t *testing.T) {
			ic := &Interceptor{enabledTools: map[string]bool{}} // simulates an empty/overridden saved setting
			if !ic.IsToolEnabled(name) {
				t.Fatalf("%s: expected mandatory floor to hold against an empty enabledTools map", name)
			}
		})
	}
}

// TestMandatoryInterceptedToolsHoldWithoutDBLoad verifies the floor applies
// even before i.enabledTools has ever been loaded (i.enabledTools == nil,
// e.g. a DB outage on first use) - checked without touching i.db at all, so
// this never attempts the (nil) DB fallback load path for floor tools.
func TestMandatoryInterceptedToolsHoldWithoutDBLoad(t *testing.T) {
	ic := &Interceptor{}
	if ic.enabledTools != nil {
		t.Fatal("test setup: expected enabledTools to start nil")
	}
	for name := range mandatoryInterceptedTools {
		if !ic.IsToolEnabled(name) {
			t.Fatalf("%s: expected mandatory floor to hold with enabledTools never loaded", name)
		}
	}
}

// TestNonMandatoryToolStillGatedBySettings verifies the floor is scoped to
// mandatoryInterceptedTools only - an ordinary tool name is unaffected and
// still reads exactly from whatever i.enabledTools holds.
func TestNonMandatoryToolStillGatedBySettings(t *testing.T) {
	const probe = "SomeCustomProbeTool"
	if mandatoryInterceptedTools[probe] {
		t.Fatalf("test setup: %q unexpectedly collides with the mandatory floor", probe)
	}
	ic := &Interceptor{enabledTools: map[string]bool{}}
	if ic.IsToolEnabled(probe) {
		t.Fatalf("%s: expected false when absent from enabledTools and not mandatory", probe)
	}
	ic.enabledTools[probe] = true
	if !ic.IsToolEnabled(probe) {
		t.Fatalf("%s: expected true once present in enabledTools", probe)
	}
}

// TestGetEnabledToolsAlwaysIncludesFloor verifies GetEnabledTools' displayed
// list always includes the mandatory floor, even when the persisted setting
// omits it entirely - so the UI never implies these tools can be turned off
// by editing the list.
func TestGetEnabledToolsAlwaysIncludesFloor(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("no test database configured")
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	ic := New(d)
	if err := ic.SetEnabledTools([]string{"OnlyThisOne"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ic.SetEnabledTools(defaultEnabledTools) })

	got, err := ic.GetEnabledTools()
	if err != nil {
		t.Fatal(err)
	}
	seen := toolSet(got)
	if !seen["OnlyThisOne"] {
		t.Fatalf("GetEnabledTools() = %v, expected to still contain the explicitly saved tool", got)
	}
	for name := range mandatoryInterceptedTools {
		if !seen[name] {
			t.Fatalf("GetEnabledTools() = %v, missing mandatory floor tool %q", got, name)
		}
	}
}
