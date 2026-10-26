package cache

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
)

// TestDoRefresh_PanicDoesNotDeadlock 验证同步刷新 panic 后 singleflight 状态被清理 ：
// panic 转成错误返回，后续调用能再次触发刷新而不是永久阻塞。
func TestDoRefresh_PanicDoesNotDeadlock(t *testing.T) {
	var calls int32
	supplier := NewCachedResultSupplier(func(context.Context) (*RefreshResult[string], error) {
		if atomic.AddInt32(&calls, 1) == 1 {
			panic("boom")
		}
		return &RefreshResult[string]{Value: "ok", StaleTime: time.Now().Add(time.Hour),
			PrefetchTime: time.Now().Add(time.Hour), ExpiresAt: time.Now().Add(time.Hour)}, nil
	}, enums.StaleValueBehaviorRefresh)

	if _, err := supplier.Get(); err == nil {
		t.Fatal("panic 应转换为错误返回")
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		result, err := supplier.Get()
		if err != nil || result == nil || result.Value != "ok" {
			t.Errorf("panic 后第二次调用应成功，得到 result=%v err=%v", result, err)
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("panic 后后续调用被永久阻塞")
	}
}

// TestDoRefresh_WaiterRespectsContext 验证等待他人刷新的调用方响应自己的 ctx。
func TestDoRefresh_WaiterRespectsContext(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{})
	supplier := NewCachedResultSupplier(func(context.Context) (*RefreshResult[string], error) {
		close(started)
		<-release
		return &RefreshResult[string]{Value: "late", ExpiresAt: time.Now().Add(time.Hour)}, nil
	}, enums.StaleValueBehaviorRefresh)
	defer close(release)

	go func() { _, _ = supplier.Get() }()
	<-started

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	begin := time.Now()
	_, err := supplier.GetWithContext(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiter 应返回 ctx 错误，得到 %v", err)
	}
	if time.Since(begin) > time.Second {
		t.Fatal("waiter 未及时响应 ctx 取消")
	}
}

// TestGetWithContext_StaleFailureBackoff 验证 stale 阶段刷新失败后进入退避窗口 ：
// 窗口内直接返回旧值，不再逐请求打 IdP；窗口过后恢复重试。
func TestGetWithContext_StaleFailureBackoff(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := NewMockClock(base)
	var calls int32
	supplier := NewCachedResultSupplier(func(context.Context) (*RefreshResult[string], error) {
		atomic.AddInt32(&calls, 1)
		return nil, errors.New("idp down")
	}, enums.StaleValueBehaviorRefresh).WithClock(clock)

	stale := &RefreshResult[string]{
		Value:        "old",
		StaleTime:    base.Add(-time.Minute),
		PrefetchTime: base.Add(-2 * time.Minute),
		ExpiresAt:    base.Add(time.Hour),
	}
	supplier.cachedResult = stale

	for i := 0; i < 5; i++ {
		result, err := supplier.Get()
		if err != nil || result != stale {
			t.Fatalf("stale 阶段刷新失败应返回旧值且无错误，得到 result=%v err=%v", result, err)
		}
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("退避窗口内应只刷新 1 次，实际 %d 次", got)
	}

	clock.Advance(defaultStaleRetryBackoff + time.Second)
	_, _ = supplier.Get()
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("退避窗口过后应恢复刷新，实际调用 %d 次", got)
	}
}

// TestGetWithContext_SuccessClearsBackoff 验证刷新成功后清除失败记录。
func TestGetWithContext_SuccessClearsBackoff(t *testing.T) {
	supplier := NewCachedResultSupplier(func(context.Context) (*RefreshResult[string], error) {
		return &RefreshResult[string]{Value: "ok", ExpiresAt: time.Now().Add(time.Hour)}, nil
	}, enums.StaleValueBehaviorRefresh)
	supplier.lastRefreshFailure = time.Now()
	if _, err := supplier.Get(); err != nil {
		t.Fatal(err)
	}
	if !supplier.lastRefreshFailure.IsZero() {
		t.Fatal("刷新成功后应清除 lastRefreshFailure")
	}
}
