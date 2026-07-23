package xray

import (
	"context"
	"fmt"
	"sync"

	"github.com/sagernet/sing/common/logger"
	xlog "github.com/xtls/xray-core/common/log"
)

// xraySinks tracks every currently-alive embedded xray-core instance's (tag, logger) pair. This
// exists because xray-core's log system is a single global handler (see
// common/log.RegisterHandler: "Previous registered handler will be discarded"), and every embedded
// xray-core instance this package creates re-registers its own app/log.Instance as part of
// xcore.New() (app/log.New() unconditionally calls log.RegisterHandler on construction - see that
// package's log.go) - so without re-registering here afterward, whichever "xray" outbound was built
// last silently owns all future log traffic from every instance, and by default that traffic goes
// nowhere a packaged app can show the user anyway: app/log.Instance.Handle only forwards
// GeneralMessages to its errorLogger, and this package's own LogConfig sets ErrorLog to "none"
// whenever it sets one at all (see xrayLogLevel).
//
// This is also precisely why a dial/handshake failure inside the embedded engine (e.g. XHTTP's
// transport-level dial) never explains itself in the app's own logs even though xray-core generated
// a real error for it: app/proxyman/outbound.Handler.Dispatch() suppresses EOF/io.ErrClosedPipe/
// context.Canceled outbound-processing errors as a clean close and logs anything else it does
// treat as a real failure (e.g. "failed to process outbound traffic") via errors.LogInfo - at
// Severity_Info, not Warning/Error, which is xray-core's own convention for connection-level
// failures (see that package's handler.go) - and has no return value for dispatch() to inspect
// regardless. The underlying cause only ever existed as an xray-core-internal log record at that
// severity, which is exactly what this now forwards. Severity is capped at Info (excluding only
// Debug) so the actual failure reason gets through while still excluding the truly high-volume
// per-packet chatter that caused the earlier trace-level, 11GB-in-seconds disk problem - see
// xrayLogLevel/XDebug for that much chattier, still-opt-in path.
//
// Because xray-core's Handler interface carries no per-instance context whatsoever (GeneralMessage
// is just {Severity, Content}, see common/log.go - nothing identifies which xcore.Instance produced
// it), a naive "whichever outbound registered most recently owns the tag" scheme is wrong far more
// often than not for any real subscription: every embedded xray-core instance constructed at
// startup re-claims the global handler in turn, so the LAST one built ends up permanently
// misattributed as the source of every other instance's traffic for the rest of the session -
// observed directly in a user-submitted log where dozens of clearly-different transports (kcp,
// grpc, xhttp, websocket, vless, vmess dials to many different servers) all appeared under one
// single outbound's tag. xraySinks tracks every instance still alive (registered in New(), removed
// in Close()) so Handle can tell the difference between "exactly one instance is active - the tag
// is trustworthy" and "N are active - the tag would be a guess," and only claims attribution in the
// former case.
var (
	xraySinksMu sync.Mutex
	xraySinks   = map[string]logger.ContextLogger{}
)

// installXrayLogForwarder (re-)registers the process-wide xray-core log handler (idempotent in
// effect - see the doc comment above for why every instance must still call this on every
// construction) and adds this outbound to the active-instance registry. The returned func removes
// it again and must be called from the outbound's Close().
func installXrayLogForwarder(tag string, sink logger.ContextLogger) (unregister func()) {
	xraySinksMu.Lock()
	xraySinks[tag] = sink
	xraySinksMu.Unlock()

	xlog.RegisterHandler(xrayLogForwarderHandler{})

	return func() {
		xraySinksMu.Lock()
		delete(xraySinks, tag)
		xraySinksMu.Unlock()
	}
}

type xrayLogForwarderHandler struct{}

func (xrayLogForwarderHandler) Handle(msg xlog.Message) {
	general, ok := msg.(*xlog.GeneralMessage)
	if !ok || general.Severity > xlog.Severity_Info {
		return
	}

	xraySinksMu.Lock()
	var tag string
	var sink logger.ContextLogger
	count := len(xraySinks)
	if count == 1 {
		for t, l := range xraySinks {
			tag, sink = t, l
		}
	} else if count > 1 {
		// Any one of them writes to the same underlying box log either way - picking one is just
		// about finding a writer, not about attribution, which is exactly what can't be trusted
		// here. Iteration order is unspecified but that's fine: which of the N active loggers
		// happens to carry this one line makes no difference to what gets written.
		for _, l := range xraySinks {
			sink = l
			break
		}
	}
	xraySinksMu.Unlock()

	if sink == nil {
		return
	}
	if count == 1 {
		sink.InfoContext(context.Background(), "xray-core[", tag, "]: ", msg.String())
		return
	}
	// count > 1: deliberately not claiming a specific outbound's tag here - it would be a guess,
	// and the earlier single-tag scheme's guesses were wrong often enough to actively mislead
	// debugging. The message's own content (destination host/port, protocol) is usually still
	// enough to tell which server it's about.
	sink.InfoContext(context.Background(), "xray-core[ambiguous, ", fmt.Sprint(count), " active xray instances]: ", msg.String())
}
