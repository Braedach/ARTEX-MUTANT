package intercept

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// failingConnector makes every query fail, simulating a database outage
// without needing a real Postgres instance.
type failingConnector struct{}

func (failingConnector) Connect(context.Context) (driver.Conn, error) {
	return nil, errors.New("simulated database outage")
}
func (failingConnector) Driver() driver.Driver { return failingDriver{} }

type failingDriver struct{}

func (failingDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("simulated database outage")
}

// TestMatchFailsTowardHumanWhenRulesUnreadable verifies that when the
// intercept rules cannot be loaded, Match returns an "ask" decision rather
// than reporting "no rule matched" (which the guard turns into default-allow
// for the mandatory-floor tools, e.g. Bash). HandleAsk then fails closed on
// its own if the database is still down, so a sustained outage denies and a
// transient one routes the call to a human.
func TestMatchFailsTowardHumanWhenRulesUnreadable(t *testing.T) {
	ic := New(&db.DB{DB: sql.OpenDB(failingConnector{})})
	for name := range mandatoryInterceptedTools {
		dec, matched := ic.Match(context.Background(), name, []byte(`{"command":"id"}`))
		if !matched {
			t.Fatalf("%s: rules unreadable but Match reported no match (would default-allow)", name)
		}
		if dec.Action != "ask" {
			t.Fatalf("%s: expected action ask, got %q", name, dec.Action)
		}
		if dec.RuleName != ruleLoadFailureRuleName {
			t.Fatalf("%s: expected rule name %q, got %q", name, ruleLoadFailureRuleName, dec.RuleName)
		}
	}
}

// TestHandleAskDeniesWhenDatabaseDown verifies the second half of the
// fail-toward-human path: with the database down no pending record can be
// created, so the approval is refused rather than granted.
func TestHandleAskDeniesWhenDatabaseDown(t *testing.T) {
	ic := New(&db.DB{DB: sql.OpenDB(failingConnector{})})
	dec, _ := ic.Match(context.Background(), "Bash", []byte(`{"command":"id"}`))
	if ic.HandleAsk(context.Background(), 0, dec, "Bash", []byte(`{"command":"id"}`)) {
		t.Fatal("expected HandleAsk to deny when no pending record can be created")
	}
}
