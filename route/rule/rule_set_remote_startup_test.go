package rule

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
	singlog "github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

type alwaysFailingHTTPTransport struct{}

func (alwaysFailingHTTPTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, E.New("simulated: no network")
}
func (alwaysFailingHTTPTransport) CloseIdleConnections() {}
func (alwaysFailingHTTPTransport) Reset()                {}

type fakeHTTPClientManager struct{}

func (fakeHTTPClientManager) ResolveTransport(context.Context, singlog.ContextLogger, option.HTTPClientOptions) (adapter.HTTPTransport, error) {
	return alwaysFailingHTTPTransport{}, nil
}
func (fakeHTTPClientManager) DefaultTransport() adapter.HTTPTransport { return alwaysFailingHTTPTransport{} }
func (fakeHTTPClientManager) ResetNetwork()                           {}

// TestRemoteRuleSetStartupTickerIsInitialized guards against a regression that shipped for a while:
// StartContext used to (correctly) set s.startupTicker = time.NewTicker(10 * time.Second) so that
// loopUpdate's retry loop - entered whenever the very first rule-set fetch fails - has something to
// wait on. A later merge silently dropped that one initializer line while leaving the field
// declaration, its use in loopUpdate's "case <-s.startupTicker.C" select, and the nil-check in
// Close() all in place. With startupTicker permanently nil, the moment any remote rule-set's initial
// fetch failed (e.g. no connectivity yet at startup, exactly the state a client is commonly in),
// evaluating "s.startupTicker.C" panicked with a nil pointer dereference and crashed the entire
// process - independent of which outbound protocol was in use, which is why it looked like unrelated
// protocols were broken.
func TestRemoteRuleSetStartupTickerIsInitialized(t *testing.T) {
	t.Parallel()

	ctx := service.ContextWith[adapter.HTTPClientManager](context.Background(), fakeHTTPClientManager{})
	ruleSet, err := NewRemoteRuleSet(ctx, log.NewNOPFactory().Logger(), option.RuleSet{
		Tag:    "test-set",
		Type:   C.RuleSetTypeRemote,
		Format: C.RuleSetFormatSource,
		RemoteOptions: option.RemoteRuleSet{
			URL:            "http://127.0.0.1:1/unreachable",
			UpdateInterval: badoption.Duration(24 * time.Hour),
		},
	})
	require.NoError(t, err)

	err = ruleSet.StartContext(ctx, adapter.NewHTTPStartContext())
	require.NoError(t, err)
	require.NotNil(t, ruleSet.startupTicker,
		"StartContext must initialize startupTicker, or loopUpdate's <-s.startupTicker.C dereferences a nil *time.Ticker and crashes the whole process the instant the initial rule-set fetch fails")
	require.True(t, ruleSet.lastUpdated.IsZero(),
		"test setup: the initial fetch must actually fail for this test to exercise the panic-prone retry loop")

	done := make(chan struct{})
	var panicVal any
	go func() {
		defer close(done)
		defer func() { panicVal = recover() }()
		ruleSet.loopUpdate()
	}()

	time.Sleep(100 * time.Millisecond)
	ruleSet.cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("loopUpdate did not exit after context cancellation")
	}
	if panicVal != nil {
		t.Fatalf("loopUpdate panicked: %v", panicVal)
	}
}
