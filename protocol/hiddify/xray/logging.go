package xray

import (
	"context"
	"sync/atomic"

	"github.com/sagernet/sing/common/logger"
	xlog "github.com/xtls/xray-core/common/log"
)

// xrayLogSink is the (tag, logger) pair the process-wide xray-core log forwarder currently
// attributes messages to.
type xrayLogSink struct {
	tag    string
	logger logger.ContextLogger
}

var activeXraySink atomic.Pointer[xrayLogSink]

// installXrayLogForwarder (re-)registers a process-wide xray-core log handler that forwards
// Warning/Error-severity messages into sing-box's own logger, and points it at this outbound as
// the current attribution target.
//
// This exists because xray-core's log system is a single global handler (see
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
// Because xray-core's Handler interface carries no per-instance context, concurrently active
// "xray" outbounds (e.g. during a URL-test sweep over many proxy entries) all funnel through
// whichever one registered most recently; messages are prefixed with that outbound's tag so the
// attribution mismatch, on the rare occasion it happens, is at least visible rather than silent.
func installXrayLogForwarder(tag string, sink logger.ContextLogger) {
	activeXraySink.Store(&xrayLogSink{tag: tag, logger: sink})
	xlog.RegisterHandler(xrayLogForwarderHandler{})
}

type xrayLogForwarderHandler struct{}

func (xrayLogForwarderHandler) Handle(msg xlog.Message) {
	general, ok := msg.(*xlog.GeneralMessage)
	if !ok || general.Severity > xlog.Severity_Info {
		return
	}
	sink := activeXraySink.Load()
	if sink == nil {
		return
	}
	sink.logger.InfoContext(context.Background(), "xray-core[", sink.tag, "]: ", msg.String())
}
