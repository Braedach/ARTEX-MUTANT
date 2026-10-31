package intercept

import (
	"errors"
	"testing"
	"time"
)

func TestLogLoadFailureLockedRateLimits(t *testing.T) {
	i := &Interceptor{}
	i.logLoadFailureLocked(errors.New("db down"))
	first := i.lastLoadFailureLog
	if first.IsZero() {
		t.Fatal("expected lastLoadFailureLog to be set after the first call")
	}
	i.logLoadFailureLocked(errors.New("db still down"))
	if !i.lastLoadFailureLog.Equal(first) {
		t.Fatal("a second call within loadFailureLogInterval must not reset the timestamp")
	}
	// Simulate the interval having elapsed.
	i.lastLoadFailureLog = time.Now().Add(-loadFailureLogInterval - time.Second)
	stale := i.lastLoadFailureLog
	i.logLoadFailureLocked(errors.New("db down again"))
	if i.lastLoadFailureLog.Equal(stale) {
		t.Fatal("a call after loadFailureLogInterval has elapsed must update the timestamp")
	}
}
