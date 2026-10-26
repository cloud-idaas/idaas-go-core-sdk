package cache

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
)

// TestBoundary_GetWithContext_ExpiresAtExactBoundary 验证 now == ExpiresAt 时不算过期。
// time.After(ExpiresAt) 返回 false，所以缓存值应被返回，不触发同步刷新。
func TestBoundary_GetWithContext_ExpiresAtExactBoundary(t *testing.T) {
	mock := NewMockClock(time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC))

	var callCount int32
	refreshFunc := func(_ context.Context) (*RefreshResult[string], error) {
		atomic.AddInt32(&callCount, 1)
		return &RefreshResult[string]{
			Value:     "cached",
			ExpiresAt: mock.Now().Add(1 * time.Hour),
		}, nil
	}

	supplier := NewCachedResultSupplier(refreshFunc, enums.StaleValueBehaviorBlock)
	supplier.clock = mock

	// 建立缓存
	result1, err := supplier.Get()
	if err != nil {
		t.Fatalf("first Get failed: %v", err)
	}
	if result1.Value != "cached" {
		t.Fatalf("first value = %q, want %q", result1.Value, "cached")
	}

	// 将时钟精确设为 ExpiresAt —— now.After(ExpiresAt) == false → 未过期
	mock.SetTime(result1.ExpiresAt)

	result2, err := supplier.GetWithContext(context.Background())
	if err != nil {
		t.Fatalf("expected no error at exact ExpiresAt, got: %v", err)
	}
	if result2 == nil || result2.Value != "cached" {
		t.Errorf("expected cached value at exact ExpiresAt, got: %v", result2)
	}
	// 不应触发额外的同步刷新
	if got := atomic.LoadInt32(&callCount); got != 1 {
		t.Errorf("callCount = %d, want 1 (no sync refresh at exact boundary)", got)
	}
}

// TestBoundary_GetWithContext_StaleBlock 验证 StaleValueBehaviorBlock 在 stale 窗口内
// 返回缓存值，不触发同步刷新。
func TestBoundary_GetWithContext_StaleBlock(t *testing.T) {
	mock := NewMockClock(time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC))

	var callCount int32
	refreshFunc := func(_ context.Context) (*RefreshResult[string], error) {
		atomic.AddInt32(&callCount, 1)
		return &RefreshResult[string]{
			Value:     "stale-block",
			ExpiresAt: mock.Now().Add(1 * time.Hour),
		}, nil
	}

	supplier := NewCachedResultSupplier(refreshFunc, enums.StaleValueBehaviorBlock)
	supplier.clock = mock

	// 建立缓存
	result1, _ := supplier.Get()
	if result1.Value != "stale-block" {
		t.Fatalf("first value = %q, want %q", result1.Value, "stale-block")
	}

	// 推进到 stale 窗口：StaleTime < now < ExpiresAt
	// StaleTime ≈ expiresAt - 12min，设 now = expiresAt - 6min
	mock.SetTime(result1.ExpiresAt.Add(-6 * time.Minute))

	result2, err := supplier.GetWithContext(context.Background())
	if err != nil {
		t.Fatalf("expected no error in stale window with Block, got: %v", err)
	}
	if result2 == nil || result2.Value != "stale-block" {
		t.Errorf("expected cached value in stale window, got: %v", result2)
	}
	// Block 在 stale 窗口不触发同步刷新，callCount 应仍为 1
	if got := atomic.LoadInt32(&callCount); got != 1 {
		t.Errorf("callCount = %d, want 1 (Block should not refresh in stale window)", got)
	}
}

// TestBoundary_GetWithContext_RefreshFuncNilNil 验证 refreshFunc 返回 (nil, nil) 时
// 不 panic,返回非 nil 错误(归一化为 ErrNilRefreshResult)。
func TestBoundary_GetWithContext_RefreshFuncNilNil(t *testing.T) {
	mock := NewMockClock(time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC))

	refreshFunc := func(_ context.Context) (*RefreshResult[string], error) {
		return nil, nil
	}

	supplier := NewCachedResultSupplier(refreshFunc, enums.StaleValueBehaviorBlock)
	supplier.clock = mock

	// cache miss → 同步刷新 → refreshFunc 返回 (nil, nil)
	// (nil, nil) 必须归一化为非 nil 错误,否则调用方解引用 result.Value panic。
	result, err := supplier.GetWithContext(context.Background())
	if err == nil {
		t.Fatalf("expected non-nil error for (nil,nil) refresh, got nil error")
	}
	if result != nil {
		t.Errorf("expected nil result for (nil,nil) refresh, got: %v", result)
	}
}

// TestBoundary_GetWithContext_InvalidateDuringAsyncRefresh 验证 Invalidate() 在异步刷新进行中时
// generation 不匹配，旧结果被丢弃。
func TestBoundary_GetWithContext_InvalidateDuringAsyncRefresh(t *testing.T) {
	mock := NewMockClock(time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC))

	// 用一个成功的 refreshFunc 建立初始缓存
	refreshFunc := func(_ context.Context) (*RefreshResult[string], error) {
		return &RefreshResult[string]{
			Value:     "initial",
			ExpiresAt: mock.Now().Add(1 * time.Hour),
		}, nil
	}

	supplier := NewCachedResultSupplier(refreshFunc, enums.StaleValueBehaviorAllow)
	supplier.clock = mock

	// 建立缓存
	r1, _ := supplier.Get()
	if r1.Value != "initial" {
		t.Fatalf("first value = %q, want %q", r1.Value, "initial")
	}

	// 替换 refreshFunc 为阻塞版本
	refreshStarted := make(chan struct{})
	refreshProceed := make(chan struct{})
	supplier.refreshFunc = func(_ context.Context) (*RefreshResult[string], error) {
		close(refreshStarted)
		<-refreshProceed
		return &RefreshResult[string]{
			Value:     "should-be-discarded",
			ExpiresAt: mock.Now().Add(1 * time.Hour),
		}, nil
	}

	// 推进到 stale 窗口触发异步刷新
	mock.SetTime(r1.ExpiresAt.Add(-6 * time.Minute))
	supplier.triggerAsyncRefresh()

	// 等待异步刷新启动
	select {
	case <-refreshStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("async refresh did not start within 2s")
	}

	// 在异步刷新进行中调用 Invalidate，generation 递增
	supplier.Invalidate()

	// 放行异步刷新
	close(refreshProceed)

	// 等待异步刷新完成
	time.Sleep(100 * time.Millisecond)

	// 由于 generation 不匹配，异步刷新结果应被丢弃，缓存应为 nil
	supplier.mu.Lock()
	cached := supplier.cachedResult
	supplier.mu.Unlock()
	if cached != nil {
		t.Errorf("expected cached result to be nil after Invalidate during async refresh, got: %v", cached)
	}
}

// TestBoundary_GetWithContext_ContextCancelled 验证:调用方在
// leader 同步刷新(cache-miss / BLOCK expired)入口传入已取消的 ctx 时,leader
// 入口短路返回 ClientRequestCanceled——不发起刷新(不消耗 IdP 配额、不登记
// in-flight)。底层 ctx.Err() 经 CacheError.Unwrap 透传,调用方可
// errors.Is(err, context.Canceled) 区分取消原因。
//
// 注:caller ctx 仅在"入口已取消"时短路;刷新一旦发起,worker 用 detached
// refresh ctx(baseCtx 派生)不被 caller ctx 取消,leader 通过
// `select{call.done|ctx.Done()}` 等待,caller 取消仅令 leader 提前返回
// ClientRequestCanceled(结果由 commitRefresh 提交给后续 waiter)。后者行为由
// TestDoRefresh_LeaderCtxCancel_StopsBlocking 覆盖。
func TestBoundary_GetWithContext_ContextCancelled(t *testing.T) {
	mock := NewMockClock(time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC))

	refreshCalled := false
	refreshFunc := func(ctx context.Context) (*RefreshResult[string], error) {
		refreshCalled = true
		return &RefreshResult[string]{
			Value:     "fresh",
			ExpiresAt: mock.Now().Add(1 * time.Hour),
		}, nil
	}

	supplier := NewCachedResultSupplier(refreshFunc, enums.StaleValueBehaviorBlock)
	supplier.clock = mock

	// 传入已取消的 context —— cache miss 走 leader 同步刷新路径,入口短路。
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, err := supplier.GetWithContext(ctx)
	// 入口短路:不发起刷新,直接返回 ClientRequestCanceled。
	if err == nil {
		t.Fatal("expected ClientRequestCanceled on pre-canceled ctx, got nil error")
	}
	if result != nil {
		t.Errorf("expected nil result on pre-canceled ctx, got: %v", result)
	}
	if refreshCalled {
		t.Error("refreshFunc must NOT be called when caller ctx is already canceled at entry (short-circuit)")
	}
	// errors.Is 链:ClientRequestCanceled → CacheError.Unwrap → ctx.Err() = context.Canceled
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected errors.Is(err, context.Canceled) via CacheError.Unwrap, got: %v", err)
	}
}

// TestBoundary_NilNilRefreshReturnsError: refreshFunc 返回 (nil, nil) 时
// 不 panic,归一化为 ErrNilRefreshResult。
func TestBoundary_NilNilRefreshReturnsError(t *testing.T) {
	mock := NewMockClock(time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC))

	refreshFunc := func(_ context.Context) (*RefreshResult[string], error) {
		return nil, nil
	}

	supplier := NewCachedResultSupplier(refreshFunc, enums.StaleValueBehaviorBlock)
	supplier.clock = mock

	// cache miss → 同步刷新 → (nil, nil) → ErrNilRefreshResult
	result, err := supplier.GetWithContext(context.Background())
	if err == nil {
		t.Fatal("expected non-nil error for (nil,nil) refresh")
	}
	if result != nil {
		t.Errorf("expected nil result for (nil,nil) refresh, got: %v", result)
	}
}

// TestBoundary_InvalidStaleValueBehaviorExpired: 未知 staleValueBehavior
// 在过期分支返回错误,不 fall-through 成功。
func TestBoundary_InvalidStaleValueBehaviorExpired(t *testing.T) {
	mock := NewMockClock(time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC))

	refreshFunc := func(_ context.Context) (*RefreshResult[string], error) {
		return &RefreshResult[string]{
			Value:     "cached",
			ExpiresAt: mock.Now().Add(1 * time.Hour),
		}, nil
	}

	// 使用无效的 staleValueBehavior
	supplier := NewCachedResultSupplier(refreshFunc, "INVALID")
	supplier.clock = mock

	// 建立缓存
	_, err := supplier.Get()
	if err != nil {
		t.Fatalf("first Get (cache miss) should not fail with INVALID behavior: %v", err)
	}

	// 推进到已过期
	mock.Advance(2 * time.Hour)

	_, err = supplier.GetWithContext(context.Background())
	if err == nil {
		t.Fatal("expected error for invalid staleValueBehavior when expired, got nil")
	}
}

// TestBoundary_InvalidStaleValueBehaviorStale: 未知 staleValueBehavior
// 在 stale 分支返回错误。
func TestBoundary_InvalidStaleValueBehaviorStale(t *testing.T) {
	mock := NewMockClock(time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC))

	refreshFunc := func(_ context.Context) (*RefreshResult[string], error) {
		return &RefreshResult[string]{
			Value:     "cached",
			ExpiresAt: mock.Now().Add(1 * time.Hour),
		}, nil
	}

	supplier := NewCachedResultSupplier(refreshFunc, "INVALID")
	supplier.clock = mock

	// 建立缓存
	_, err := supplier.Get()
	if err != nil {
		t.Fatalf("first Get (cache miss) should not fail: %v", err)
	}

	// 推进到 stale 窗口（StaleTime 为零值，任何 advance 都进入 stale）
	mock.Advance(1 * time.Minute)

	_, err = supplier.GetWithContext(context.Background())
	if err == nil {
		t.Fatal("expected error for invalid staleValueBehavior in stale window, got nil")
	}
}

// TestBoundary_InvalidateDuringRefreshReturnsInvalidatedError: 当 Invalidate()
// 在刷新进行中运行时,waiter 收到 ErrRefreshInvalidated 而非 stale-generation 凭证。
func TestBoundary_InvalidateDuringRefreshReturnsInvalidatedError(t *testing.T) {
	mock := NewMockClock(time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC))

	refreshStarted := make(chan struct{})
	refreshProceed := make(chan struct{})

	refreshFunc := func(_ context.Context) (*RefreshResult[string], error) {
		close(refreshStarted)
		<-refreshProceed
		return &RefreshResult[string]{
			Value:     "should-be-discarded",
			ExpiresAt: mock.Now().Add(1 * time.Hour),
		}, nil
	}

	supplier := NewCachedResultSupplier(refreshFunc, enums.StaleValueBehaviorBlock)
	supplier.clock = mock

	// cache miss → leader 发起同步刷新
	// 在另一个 goroutine 中发起 Get（leader）
	type getResult struct {
		result *RefreshResult[string]
		err    error
	}
	leaderCh := make(chan getResult, 1)
	go func() {
		r, e := supplier.GetWithContext(context.Background())
		leaderCh <- getResult{r, e}
	}()

	// 等待 leader 的 refreshFunc 启动
	select {
	case <-refreshStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("leader refresh did not start within 2s")
	}

	// 在刷新进行中调用 Invalidate，generation 递增
	supplier.Invalidate()

	// 放行 leader 的 refreshFunc
	close(refreshProceed)

	// leader 应收到 ErrRefreshInvalidated（generation 不匹配）
	select {
	case res := <-leaderCh:
		if res.err == nil {
			t.Fatal("expected leader to get error after Invalidate, got nil")
		}
		if res.result != nil {
			t.Errorf("expected nil result after Invalidate, got: %v", res.result)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("leader Get did not return within 2s after Invalidate")
	}
}

// TestBoundary_AllowExpiredReturnsStaleValueAndError: ALLOW 策略在过期分支
// 返回 (cached, ErrStaleCredentialReturned),supplier 层契约验证。
func TestBoundary_AllowExpiredReturnsStaleValueAndError(t *testing.T) {
	mock := NewMockClock(time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC))

	refreshFunc := func(_ context.Context) (*RefreshResult[string], error) {
		return &RefreshResult[string]{
			Value:     "stale-value",
			ExpiresAt: mock.Now().Add(1 * time.Hour),
		}, nil
	}

	supplier := NewCachedResultSupplier(refreshFunc, enums.StaleValueBehaviorAllow)
	supplier.clock = mock

	// 建立缓存
	r1, err := supplier.Get()
	if err != nil {
		t.Fatalf("first Get failed: %v", err)
	}
	if r1.Value != "stale-value" {
		t.Fatalf("first value = %q, want %q", r1.Value, "stale-value")
	}

	// 推进到已过期
	mock.SetTime(r1.ExpiresAt.Add(1 * time.Minute))

	// ALLOW 过期：应返回 (cached, ErrStaleCredentialReturned)
	result, err := supplier.GetWithContext(context.Background())
	if err == nil {
		t.Fatal("expected ErrStaleCredentialReturned for expired ALLOW, got nil error")
	}
	if result == nil {
		t.Fatal("expected cached result for expired ALLOW, got nil result")
	}
	if result.Value != "stale-value" {
		t.Errorf("expected stale value %q, got %q", "stale-value", result.Value)
	}
}

// TestBoundary_AllowExpiredBackoffSuppressesAsyncRefresh: ALLOW 过期分支
// 在退避窗口内不再触发后台刷新。
func TestBoundary_AllowExpiredBackoffSuppressesAsyncRefresh(t *testing.T) {
	mock := NewMockClock(time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC))

	var callCount int32
	refreshFunc := func(_ context.Context) (*RefreshResult[string], error) {
		atomic.AddInt32(&callCount, 1)
		// 第一次成功建缓存，之后返回错误
		if atomic.LoadInt32(&callCount) == 1 {
			return &RefreshResult[string]{
				Value:     "initial",
				ExpiresAt: mock.Now().Add(1 * time.Hour),
			}, nil
		}
		return nil, errors.New("refresh failed")
	}

	supplier := NewCachedResultSupplier(refreshFunc, enums.StaleValueBehaviorAllow)
	supplier.clock = mock
	// 缩短退避窗口使测试更快
	supplier.staleRetryBackoff = 1 * time.Minute

	// 建立缓存
	r1, _ := supplier.Get()
	if r1.Value != "initial" {
		t.Fatalf("first value = %q, want %q", r1.Value, "initial")
	}

	// 推进到已过期
	mock.SetTime(r1.ExpiresAt.Add(1 * time.Minute))

	// 第一次过期调用：触发异步刷新（会失败，设置 lastRefreshFailure）
	_, err := supplier.GetWithContext(context.Background())
	if err == nil {
		t.Fatal("expected ErrStaleCredentialReturned for expired ALLOW")
	}

	// 异步刷新可能还未完成，等待一下
	time.Sleep(100 * time.Millisecond)
	callCountAfterWait := atomic.LoadInt32(&callCount)

	// 第二次过期调用（仍在退避窗口内）：不应触发额外的异步刷新
	_, err = supplier.GetWithContext(context.Background())
	if err == nil {
		t.Fatal("expected ErrStaleCredentialReturned for expired ALLOW in backoff")
	}

	time.Sleep(100 * time.Millisecond)
	callCountFinal := atomic.LoadInt32(&callCount)

	// 退避窗口内不应有额外的刷新调用（允许异步刷新的那一次，但不应有更多）
	if callCountFinal > callCountAfterWait+1 {
		t.Errorf("backoff should suppress async refresh, callCount went from %d to %d",
			callCountAfterWait, callCountFinal)
	}
}

// TestBoundary_BlockExpired_Backoff_FastFail 验证:BLOCK expired 分支
// 在退避窗口内 fast-fail 返回 ErrRefreshInBackoff(防 IdP 雪崩),窗口外才同步刷新。
// BLOCK 硬保证"不返回过期值"仍成立(返回错误而非旧值)。
func TestBoundary_BlockExpired_Backoff_FastFail(t *testing.T) {
	mock := NewMockClock(time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC))

	var callCount int32
	refreshFunc := func(_ context.Context) (*RefreshResult[string], error) {
		atomic.AddInt32(&callCount, 1)
		return nil, errors.New("idp down")
	}

	supplier := NewCachedResultSupplier(refreshFunc, enums.StaleValueBehaviorBlock)
	supplier.clock = mock
	// 缩短退避窗到 1 分钟,使"窗外重试"在测试尺度内可达。
	supplier.staleRetryBackoff = 1 * time.Minute

	// 建立初始缓存(用一次成功 refreshFunc 之外的注入)。
	// refreshFunc 恒失败,故先直接 Put 一个会过期的缓存。
	cached := &RefreshResult[string]{
		Value:     "initial",
		ExpiresAt: mock.Now().Add(1 * time.Hour),
	}
	supplier.mu.Lock()
	supplier.cachedResult = cached
	supplier.mu.Unlock()

	// 推进到已过期
	mock.SetTime(cached.ExpiresAt.Add(1 * time.Minute))

	// 第一次 expired BLOCK 调用:不在退避窗(无 prior failure)→ doRefresh → 失败 →
	// commitRefresh 设 lastRefreshFailure。
	_, err := supplier.GetWithContext(context.Background())
	if err == nil {
		t.Fatal("expected error on first expired BLOCK refresh failure")
	}
	// 首次失败应是 refreshFunc 的错(非 ErrRefreshInBackoff);若走到 backoff 路径
	// 说明前置状态不对。此处只断言非 nil 即可,无需空分支。
	firstCalls := atomic.LoadInt32(&callCount)
	if firstCalls != 1 {
		t.Fatalf("first expired BLOCK should trigger exactly 1 doRefresh, got %d", firstCalls)
	}

	// 第二次 expired BLOCK 调用:仍在退避窗内(1min)→ 立即 ErrRefreshInBackoff,不再打 IdP。
	_, err = supplier.GetWithContext(context.Background())
	if !errors.Is(err, ErrRefreshInBackoff) {
		t.Fatalf("expected ErrRefreshInBackoff within backoff window, got %v", err)
	}
	if got := atomic.LoadInt32(&callCount); got != 1 {
		t.Errorf("backoff should suppress doRefresh, callCount = %d, want 1", got)
	}

	// 第三次:推进时钟越过退避窗 → 重试 doRefresh(再次失败)。
	mock.SetTime(cached.ExpiresAt.Add(1 * time.Minute).Add(2 * time.Minute)) // +2min > 1min backoff
	_, err = supplier.GetWithContext(context.Background())
	if err == nil {
		t.Fatal("expected error after backoff retry failure")
	}
	if got := atomic.LoadInt32(&callCount); got != 2 {
		t.Errorf("after backoff window should retry doRefresh, callCount = %d, want 2", got)
	}
}
