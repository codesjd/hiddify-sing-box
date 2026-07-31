package monitoring

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
)

// countingLogger wraps a NOP logger and counts Info() calls, which is exactly the one log line
// startCycleOnce's goroutine emits per actual cycle run - a proxy for "how many full monitoring
// cycles actually executed".
type countingLogger struct {
	log.ContextLogger
	mu    sync.Mutex
	count int
}

func (c *countingLogger) Info(args ...any) {
	c.mu.Lock()
	c.count++
	c.mu.Unlock()
}

func (c *countingLogger) Count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.count
}

// TestInterfaceUpdatedCoalescesRapidCalls guards a real regression: InterfaceUpdated used to call
// startCycleOnce with no cooldown at all, so on a flapping network connection - where the platform
// fires network-change notifications many times a second - each one kicked off a brand-new full
// outbound x fallback-URL monitoring cycle the instant the previous one finished. Against a real
// user's ~46-outbound profile this produced tens of thousands of dial attempts against the same
// server within minutes, entirely self-inflicted. startCycleOnce must coalesce a burst of rapid
// calls into at most one immediate cycle plus at most one more after cycleCooldown, not one cycle
// per call.
func TestInterfaceUpdatedCoalescesRapidCalls(t *testing.T) {
	logger := &countingLogger{ContextLogger: log.NewNOPFactory().Logger()}

	m := &OutboundMonitoring{
		ctx:           context.Background(),
		logger:        logger,
		outbounds:     map[string]*outboundState{},
		groups:        map[string]*groupState{},
		cycleCooldown: 50 * time.Millisecond,
	}

	// Simulate a flapping interface: hammer InterfaceUpdated continuously (as fast as the scheduler
	// allows, no delay between calls) for a fixed wall-clock window. A trivial empty-outbounds
	// cycle completes in well under a microsecond, so without a cooldown the CAS guard alone barely
	// slows anything down - the number of completed cycles would scale with the call rate, not with
	// wall-clock time. With the cooldown fix, completed cycles must be bounded by
	// window / cycleCooldown regardless of how fast or how many times InterfaceUpdated is called.
	const window = 220 * time.Millisecond
	deadline := time.Now().Add(window)
	for time.Now().Before(deadline) {
		m.InterfaceUpdated()
	}

	// Let any in-flight cooldown-deferred retry settle.
	time.Sleep(3 * m.cycleCooldown)

	count := logger.Count()
	maxExpected := int(window/m.cycleCooldown) + 3 // + slack for the immediate first cycle and timing jitter
	if count > maxExpected {
		t.Fatalf("expected continuous InterfaceUpdated calls over %s with a %s cooldown to produce at most ~%d cycles, got %d - regression: no cooldown/coalescing lets cycle rate scale with call rate instead of wall-clock time", window, m.cycleCooldown, maxExpected, count)
	}
	if count == 0 {
		t.Fatalf("expected at least one cycle to have run")
	}

	// No further calls: the count must not keep climbing on its own.
	settledAt := count
	time.Sleep(300 * time.Millisecond)
	if settled := logger.Count(); settled != settledAt {
		t.Fatalf("expected cycle count to settle at %d once calls stop, got %d", settledAt, settled)
	}
}
