package factory

import (
	"sync"
	"testing"
	"time"

	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
)

// recordingListener 记录所有回调,供测试断言。
type recordingListener struct {
	mu                      sync.Mutex
	refreshedCount          int
	refreshFailedCount      int
	degradationEnteredCount int
	degradationExitedCount  int
	lastExpiresAt           time.Time
	lastScope               string
	lastWillRetry           bool
	lastConsecutiveFailures int
	lastExitedState         enums.TokenState
}

func (r *recordingListener) OnTokenRefreshed(expiresAt time.Time, scope string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.refreshedCount++
	r.lastExpiresAt = expiresAt
	r.lastScope = scope
}

func (r *recordingListener) OnTokenRefreshFailed(err error, willRetry bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.refreshFailedCount++
	r.lastWillRetry = willRetry
}

func (r *recordingListener) OnDegradationEntered(consecutiveFailures int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.degradationEnteredCount++
	r.lastConsecutiveFailures = consecutiveFailures
}

func (r *recordingListener) OnDegradationExited(tokenState enums.TokenState) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.degradationExitedCount++
	r.lastExitedState = tokenState
}

func TestTokenListenerInterfaceCompiles(t *testing.T) {
	var _ TokenListener = (*recordingListener)(nil)
}

func TestAddTokenListenerStoresListener(t *testing.T) {
	f := &IDaaSCredentialProviderFactory{}
	l := &recordingListener{}

	f.AddTokenListener(l)

	f.listenersMu.RLock()
	count := len(f.listeners)
	f.listenersMu.RUnlock()

	if count != 1 {
		t.Errorf("expected 1 listener, got %d", count)
	}
}

func TestAddNilListenerIgnored(t *testing.T) {
	f := &IDaaSCredentialProviderFactory{}
	f.AddTokenListener(nil)

	f.listenersMu.RLock()
	count := len(f.listeners)
	f.listenersMu.RUnlock()

	if count != 0 {
		t.Errorf("nil listener should be ignored, got %d", count)
	}
}
