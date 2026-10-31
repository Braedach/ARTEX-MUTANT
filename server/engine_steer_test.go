package server

import (
	"strings"
	"testing"
)

// newSteerTestEngine builds just enough of an Engine for SteerWork/drainSteer -
// no Manager needed, since those two only touch work/steerBox and their mutexes.
func newSteerTestEngine(intentID int64) *Engine {
	e := &Engine{work: map[int64]*workExecution{intentID: {}}, steerBox: map[int64][]string{}}
	return e
}

func TestSteerWorkRejectsOversizedMessage(t *testing.T) {
	e := newSteerTestEngine(1)
	long := strings.Repeat("a", maxSteerMsgRunes+1)
	if err := e.SteerWork(1, long); err == nil {
		t.Fatal("expected an over-length steer message to be rejected")
	}
	if got, ok := e.drainSteer(1); ok {
		t.Fatalf("rejected message must not have been queued, got %q", got)
	}
}

func TestSteerWorkAllowsMessageAtLimit(t *testing.T) {
	e := newSteerTestEngine(1)
	exact := strings.Repeat("a", maxSteerMsgRunes)
	if err := e.SteerWork(1, exact); err != nil {
		t.Fatalf("a message exactly at the limit must be accepted: %v", err)
	}
}

func TestSteerWorkRejectsQueueOverflow(t *testing.T) {
	e := newSteerTestEngine(1)
	for i := 0; i < maxSteerQueueLen; i++ {
		if err := e.SteerWork(1, "correction"); err != nil {
			t.Fatalf("message %d of %d should have been accepted: %v", i+1, maxSteerQueueLen, err)
		}
	}
	if err := e.SteerWork(1, "one too many"); err == nil {
		t.Fatal("expected the queue-overflow message to be rejected")
	}
	// Draining must still yield exactly maxSteerQueueLen messages, in order.
	for i := 0; i < maxSteerQueueLen; i++ {
		if _, ok := e.drainSteer(1); !ok {
			t.Fatalf("expected a queued message at position %d", i)
		}
	}
	if _, ok := e.drainSteer(1); ok {
		t.Fatal("queue should be empty after draining exactly maxSteerQueueLen messages")
	}
}
