package factory

import (
	"testing"
	"time"

	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
)

// noopListener 是 TokenListener 的无操作实现,用于验证 Reset 清空 listeners。
type noopListener struct{}

func (noopListener) OnTokenRefreshed(time.Time, string)   {}
func (noopListener) OnTokenRefreshFailed(error, bool)     {}
func (noopListener) OnDegradationEntered(int)             {}
func (noopListener) OnDegradationExited(enums.TokenState) {}

// TestFactory_Reset_ClearsListeners 验证 Reset 必须清空已注册的 TokenListener。
//
// Reset 清空 providers / exchangeProviders / warmupCancel / warmupDone /
// initGeneration 与 listeners:重新 Initialize 后,旧生命周期的 listener 不应
// 残留并被新生命周期的刷新事件触发,避免跨生命周期回调和 use-after-reset。
func TestFactory_Reset_ClearsListeners(t *testing.T) {
	Reset()
	defer Reset()

	f := GetInstance()

	// 注册两个 listener。
	f.AddTokenListener(noopListener{})
	f.AddTokenListener(noopListener{})

	f.listenersMu.RLock()
	count := len(f.listeners)
	f.listenersMu.RUnlock()
	if count != 2 {
		t.Fatalf("expected 2 listeners registered before Reset, got %d", count)
	}

	f.Reset()

	f.listenersMu.RLock()
	after := len(f.listeners)
	f.listenersMu.RUnlock()
	if after != 0 {
		t.Errorf("Reset should clear listeners, got %d remaining after Reset", after)
	}
}

// TestFactory_Reset_NilListenersNoPanic Reset 在 listeners 为空时不应 panic。
func TestFactory_Reset_NilListenersNoPanic(t *testing.T) {
	Reset()
	defer Reset()

	f := GetInstance()
	f.mu.Lock()
	f.initialized = true
	f.listenersMu.Lock()
	f.listeners = nil
	f.listenersMu.Unlock()
	f.mu.Unlock()

	// 不应 panic。
	f.Reset()

	f.listenersMu.RLock()
	after := len(f.listeners)
	f.listenersMu.RUnlock()
	if after != 0 {
		t.Errorf("expected 0 listeners after Reset on nil, got %d", after)
	}
}
