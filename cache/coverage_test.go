package cache

import (
	"context"
	"errors"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
)

// TestJitter_NormalRange 正常 TTL 下 jitter 返回值在 [t+lo, t+hi] 且 <= expiresAt - SafetyMargin。
func TestJitter_NormalRange(t *testing.T) {
	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	expiresAt := t0.Add(1 * time.Hour)

	result := jitter(t0, expiresAt)

	ceiling := expiresAt.Add(-SafetyMargin)
	if result.Before(t0) {
		t.Errorf("jitter result %v before base %v", result, t0)
	}
	if result.After(ceiling) {
		t.Errorf("jitter result %v after ceiling %v", result, ceiling)
	}
}

// TestJitter_MultipleCallsDistribution 多次调用应产生不同的值（随机性验证）。
func TestJitter_MultipleCallsDistribution(t *testing.T) {
	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	expiresAt := t0.Add(1 * time.Hour)

	seen := make(map[time.Time]bool)
	for i := 0; i < 50; i++ {
		v := jitter(t0, expiresAt)
		seen[v] = true
	}
	// 50 次随机调用在 [t+5min, t+10min] 的区间内应该至少出现 2 个不同值
	if len(seen) < 2 {
		t.Errorf("jitter produced only %d distinct values in 50 calls, expected randomization", len(seen))
	}
}

// TestJitter_CeilingNotAfterBase 当 expiresAt-SafetyMargin <= t 时返回 t。
func TestJitter_CeilingNotAfterBase(t *testing.T) {
	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	// expiresAt = t0 + SafetyMargin → ceiling = t0 → ceiling not after t0
	expiresAt := t0.Add(SafetyMargin)
	result := jitter(t0, expiresAt)
	if !result.Equal(t0) {
		t.Errorf("jitter with ceiling<=base = %v, want %v", result, t0)
	}
}

// TestJitter_TinyTtl TTL 非常小导致 hi > room，区间收缩后 lo 可能 > hi。
func TestJitter_TinyTtl(t *testing.T) {
	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	// room = SafetyMargin - 1ns → 非常小
	expiresAt := t0.Add(SafetyMargin - 1*time.Nanosecond)
	result := jitter(t0, expiresAt)

	// hi = room (very small), lo > hi → lo=0, hi<=lo → return t0
	if !result.Equal(t0) {
		ceiling := expiresAt.Add(-SafetyMargin)
		if result.Before(t0) || result.After(ceiling) {
			t.Errorf("jitter result %v out of [t0, ceiling=%v]", result, ceiling)
		}
	}
}

// TestJitter_ShortTtl Room 小于 hi 但大于 lo → 区间收缩。
func TestJitter_ShortTtl(t *testing.T) {
	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	// room = 7 min → 大于 JitterStart (5min) 但小于 hi (10min)
	expiresAt := t0.Add(SafetyMargin + 7*time.Minute)
	result := jitter(t0, expiresAt)

	ceiling := expiresAt.Add(-SafetyMargin)
	if result.Before(t0) {
		t.Errorf("jitter result %v before base %v", result, t0)
	}
	if result.After(ceiling) {
		t.Errorf("jitter result %v after ceiling %v", result, ceiling)
	}
}

// TestReadCryptoSeed_NotZero 正常调用不应返回 0 (极大概率)。
func TestReadCryptoSeed_NotZero(t *testing.T) {
	seed := readCryptoSeed()
	if seed == 0 {
		// 多试几次
		for i := 0; i < 5; i++ {
			seed = readCryptoSeed()
			if seed != 0 {
				break
			}
		}
		if seed == 0 {
			t.Log("readCryptoSeed returned 0 repeatedly (extremely unlikely, but not a failure)")
		}
	}
}

// TestNewRefreshResult_BasicTimeComputation 验证 StaleTime / PrefetchTime / ExpiresAt 的计算。
func TestNewRefreshResult_BasicTimeComputation(t *testing.T) {
	base := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	mock := NewMockClock(base)
	SetClock(mock)
	defer SetClock(&SystemClock{})

	expiresIn := int64(3600) // 1 小时
	result, _ := NewRefreshResult("token-value", base, expiresIn)

	expectedExpiresAt := base.Add(time.Duration(expiresIn) * time.Second)
	if !result.ExpiresAt.Equal(expectedExpiresAt) {
		t.Errorf("ExpiresAt = %v, want %v", result.ExpiresAt, expectedExpiresAt)
	}

	// baseStale = expiresAt - 1h/5 = expiresAt - 12min
	baseStale := expectedExpiresAt.Add(-time.Duration(expiresIn) * time.Second / 5)
	// basePrefetch = expiresAt - 1h/3 = expiresAt - 20min
	basePrefetch := expectedExpiresAt.Add(-time.Duration(expiresIn) * time.Second / 3)

	ceiling := expectedExpiresAt.Add(-SafetyMargin)
	if result.StaleTime.Before(baseStale) {
		t.Errorf("StaleTime %v before base %v", result.StaleTime, baseStale)
	}
	if result.StaleTime.After(ceiling) {
		t.Errorf("StaleTime %v after ceiling %v", result.StaleTime, ceiling)
	}
	if result.PrefetchTime.Before(basePrefetch) {
		t.Errorf("PrefetchTime %v before base %v", result.PrefetchTime, basePrefetch)
	}
	if result.PrefetchTime.After(ceiling) {
		t.Errorf("PrefetchTime %v after ceiling %v", result.PrefetchTime, ceiling)
	}

	if result.StaleTime.Before(result.PrefetchTime) {
		t.Errorf("StaleTime %v should be >= PrefetchTime %v", result.StaleTime, result.PrefetchTime)
	}
}

// TestNewRefreshResult_ZeroReceivedAt receivedAt 为零值时使用 Clock.Now()。
func TestNewRefreshResult_ZeroReceivedAt(t *testing.T) {
	base := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	mock := NewMockClock(base)
	SetClock(mock)
	defer SetClock(&SystemClock{})

	result, _ := NewRefreshResult(42, time.Time{}, 60)
	expectedExpiresAt := base.Add(60 * time.Second)
	if !result.ExpiresAt.Equal(expectedExpiresAt) {
		t.Errorf("ExpiresAt = %v, want %v (based on clock.Now)", result.ExpiresAt, expectedExpiresAt)
	}
	if result.Value != 42 {
		t.Errorf("Value = %v, want 42", result.Value)
	}
}

// TestNewRefreshResult_StructValue 泛型使用 struct 类型。
func TestNewRefreshResult_StructValue(t *testing.T) {
	type Token struct {
		AccessToken string
		ExpiresIn   int
	}
	val := Token{AccessToken: "abc", ExpiresIn: 3600}
	result, _ := NewRefreshResult(val, time.Now(), 3600)
	if result.Value.AccessToken != "abc" {
		t.Errorf("Value.AccessToken = %q, want %q", result.Value.AccessToken, "abc")
	}
}

// TestRefreshResult_IsStale_NotStale 未进入 stale 阶段。
func TestRefreshResult_IsStale_NotStale(t *testing.T) {
	now := time.Now()
	mock := NewMockClock(now)
	SetClock(mock)
	defer SetClock(&SystemClock{})

	r := &RefreshResult[string]{
		StaleTime: now.Add(1 * time.Hour),
		ExpiresAt: now.Add(2 * time.Hour),
	}
	if r.IsStale() {
		t.Error("should not be stale when now < StaleTime")
	}
}

// TestRefreshResult_IsStale_InStaleWindow 在 stale 窗口内。
func TestRefreshResult_IsStale_InStaleWindow(t *testing.T) {
	now := time.Now()
	mock := NewMockClock(now)
	SetClock(mock)
	defer SetClock(&SystemClock{})

	r := &RefreshResult[string]{
		StaleTime: now.Add(-1 * time.Hour),
		ExpiresAt: now.Add(1 * time.Hour),
	}
	if !r.IsStale() {
		t.Error("should be stale when StaleTime < now < ExpiresAt")
	}
}

// TestRefreshResult_IsStale_Expired 已过期不算 stale。
func TestRefreshResult_IsStale_Expired(t *testing.T) {
	now := time.Now()
	mock := NewMockClock(now)
	SetClock(mock)
	defer SetClock(&SystemClock{})

	r := &RefreshResult[string]{
		StaleTime: now.Add(-2 * time.Hour),
		ExpiresAt: now.Add(-1 * time.Hour),
	}
	if r.IsStale() {
		t.Error("should not be stale when now > ExpiresAt")
	}
}

// TestRefreshResult_ShouldPrefetch_NotReached 未到预取时间。
func TestRefreshResult_ShouldPrefetch_NotReached(t *testing.T) {
	now := time.Now()
	mock := NewMockClock(now)
	SetClock(mock)
	defer SetClock(&SystemClock{})

	r := &RefreshResult[string]{
		PrefetchTime: now.Add(1 * time.Hour),
	}
	if r.ShouldPrefetch() {
		t.Error("should not prefetch when now < PrefetchTime")
	}
}

// TestRefreshResult_ShouldPrefetch_Reached 到达预取时间。
func TestRefreshResult_ShouldPrefetch_Reached(t *testing.T) {
	now := time.Now()
	mock := NewMockClock(now)
	SetClock(mock)
	defer SetClock(&SystemClock{})

	r := &RefreshResult[string]{
		PrefetchTime: now.Add(-1 * time.Hour),
	}
	if !r.ShouldPrefetch() {
		t.Error("should prefetch when now > PrefetchTime")
	}
}

// TestSetClock_GetClock 设置和获取时钟。
func TestSetClock_GetClock(t *testing.T) {
	original := GetClock()
	defer SetClock(original)

	mock := NewMockClock(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))
	SetClock(mock)

	got := GetClock()
	if got != mock {
		t.Error("GetClock() should return the mock set by SetClock")
	}
}

// TestSetClock_RestoreSystemClock 恢复系统时钟。
func TestSetClock_RestoreSystemClock(t *testing.T) {
	mock := NewMockClock(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))
	SetClock(mock)
	SetClock(&SystemClock{})

	got := GetClock()
	if _, ok := got.(*SystemClock); !ok {
		t.Error("GetClock() should return *SystemClock after restoring")
	}
}

// TestCachedResultSupplier_WithClock 注入 Clock 并验证。
func TestCachedResultSupplier_WithClock(t *testing.T) {
	mock := NewMockClock(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))
	supplier := NewCachedResultSupplier(
		func(_ context.Context) (*RefreshResult[string], error) {
			return &RefreshResult[string]{Value: "v", ExpiresAt: time.Now().Add(1 * time.Hour)}, nil
		},
		enums.StaleValueBehaviorBlock,
	)
	supplier = supplier.WithClock(mock)

	if supplier.clock != mock {
		t.Error("WithClock did not set the clock")
	}
}

// TestCachedResultSupplier_WithClock_Nil 传入 nil 不应替换。
func TestCachedResultSupplier_WithClock_Nil(t *testing.T) {
	original := &SystemClock{}
	supplier := &CachedResultSupplier[string]{
		clock: original,
	}
	ret := supplier.WithClock(nil)
	if supplier.clock != original {
		t.Error("WithClock(nil) should not replace existing clock")
	}
	if ret != supplier {
		t.Error("WithClock should return the supplier for chaining")
	}
}

// TestCachedResultSupplier_WithPrefetchStrategy 注入预取策略。
func TestCachedResultSupplier_WithPrefetchStrategy(t *testing.T) {
	strategy := &testPrefetchStrategy{called: false}
	supplier := NewCachedResultSupplier(
		func(_ context.Context) (*RefreshResult[string], error) {
			return &RefreshResult[string]{Value: "v", ExpiresAt: time.Now().Add(1 * time.Hour)}, nil
		},
		enums.StaleValueBehaviorBlock,
	)
	supplier = supplier.WithPrefetchStrategy(strategy)

	if supplier.prefetchStrategy != strategy {
		t.Fatal("WithPrefetchStrategy did not set the strategy")
	}

	// 先建缓存，然后触发异步刷新（应该委托给策略）
	_, _ = supplier.Get()
	// 让缓存进入可预取区域
	time.Sleep(10 * time.Millisecond)
	supplier.triggerAsyncRefresh()

	if !strategy.called {
		t.Error("triggerAsyncRefresh should delegate to PrefetchStrategy.Prefetch")
	}
}

// TestCachedResultSupplier_WithPrefetchStrategy_Nil 传入 nil 不应替换。
func TestCachedResultSupplier_WithPrefetchStrategy_Nil(t *testing.T) {
	supplier := &CachedResultSupplier[string]{}
	ret := supplier.WithPrefetchStrategy(nil)
	if supplier.prefetchStrategy != nil {
		t.Error("WithPrefetchStrategy(nil) should not set strategy")
	}
	if ret != supplier {
		t.Error("WithPrefetchStrategy should return the supplier for chaining")
	}
}

// testPrefetchStrategy 实现了 PrefetchStrategy 接口。
type testPrefetchStrategy struct {
	called bool
}

func (m *testPrefetchStrategy) Prefetch(refresh func()) {
	m.called = true
	refresh()
}

func (m *testPrefetchStrategy) Close() error {
	return nil
}

// TestTriggerAsyncRefresh_DefaultBehavior 无策略时走默认 goroutine 路径。
func TestTriggerAsyncRefresh_DefaultBehavior(t *testing.T) {
	supplier := NewCachedResultSupplier(
		func(_ context.Context) (*RefreshResult[string], error) {
			return &RefreshResult[string]{
				Value:     "refreshed",
				ExpiresAt: time.Now().Add(1 * time.Hour),
			}, nil
		},
		enums.StaleValueBehaviorBlock,
	)

	_, _ = supplier.Get()
	supplier.triggerAsyncRefresh()
	time.Sleep(100 * time.Millisecond)
}

// TestJitter_RoomBetweenZeroAndJitterStart room 小于 JitterStart 导致 lo > hi → lo=0。
func TestJitter_RoomBetweenZeroAndJitterStart(t *testing.T) {
	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	// room = 3min → 大于 0 但小于 JitterStart (5min)
	// hi = 10min > 3min → hi = 3min
	// lo = 5min > hi = 3min → lo = 0
	expiresAt := t0.Add(SafetyMargin + 3*time.Minute)
	result := jitter(t0, expiresAt)

	ceiling := expiresAt.Add(-SafetyMargin)
	if result.Before(t0) {
		t.Errorf("jitter result %v before base %v", result, t0)
	}
	if result.After(ceiling) {
		t.Errorf("jitter result %v after ceiling %v", result, ceiling)
	}
}

// TestJitter_RoomExactlyJitterStart room 恰好等于 JitterStart → hi==lo → return t。
func TestJitter_RoomExactlyJitterStart(t *testing.T) {
	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	// room = JitterStart = 5min
	// hi = 10min > 5min → hi = 5min
	// lo = 5min, lo > hi? 5min > 5min → no → lo stays 5min
	// hi <= lo? 5min <= 5min → yes → return t0
	expiresAt := t0.Add(SafetyMargin + JitterStart)
	result := jitter(t0, expiresAt)
	if !result.Equal(t0) {
		t.Errorf("jitter with room==JitterStart = %v, want %v", result, t0)
	}
}

// TestGetWithContext_Stale_Allow stale 但未过期 + Allow → 返回旧值并异步刷新。
func TestGetWithContext_Stale_Allow(t *testing.T) {
	mock := NewMockClock(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))

	// 异步刷新在后台 goroutine 中执行，计数需原子读写，否则 -race 报数据竞争。
	var callCount int32

	refreshFunc := func(_ context.Context) (*RefreshResult[string], error) {
		atomic.AddInt32(&callCount, 1)
		return &RefreshResult[string]{
			Value:     "fresh",
			ExpiresAt: mock.Now().Add(1 * time.Hour),
		}, nil
	}

	supplier := NewCachedResultSupplier(refreshFunc, enums.StaleValueBehaviorAllow)
	supplier.clock = mock

	// 第一次调用建立缓存（过期时间在 1 小时后）
	result1, err := supplier.Get()
	if err != nil {
		t.Fatalf("first Get failed: %v", err)
	}
	if result1.Value != "fresh" {
		t.Fatalf("first value = %q, want %q", result1.Value, "fresh")
	}

	// 推进时间到 stale 阶段（StaleTime < now < ExpiresAt）
	// StaleTime ≈ expiresAt - 1h/5 = expiresAt - 12min
	// 设置 now = expiresAt - 6min（已过 stale 但未过期）
	mock.SetTime(result1.ExpiresAt.Add(-6 * time.Minute))

	result2, err := supplier.Get()
	if err != nil {
		t.Fatalf("stale Get should not return error for Allow: %v", err)
	}
	if result2.Value != "fresh" {
		t.Errorf("stale Allow should return cached value %q, got %q", "fresh", result2.Value)
	}

	// 等待异步刷新
	deadline := time.Now().Add(time.Second)
	for atomic.LoadInt32(&callCount) < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if n := atomic.LoadInt32(&callCount); n < 2 {
		t.Errorf("async refresh should have been triggered, callCount=%d", n)
	}
}

// TestGetWithContext_Stale_Refresh stale 但未过期 + Refresh → 同步刷新。
func TestGetWithContext_Stale_Refresh(t *testing.T) {
	mock := NewMockClock(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))

	callCount := 0
	refreshFunc := func(_ context.Context) (*RefreshResult[string], error) {
		callCount++
		val := "v" + string(rune('0'+callCount))
		return &RefreshResult[string]{
			Value:     val,
			ExpiresAt: mock.Now().Add(1 * time.Hour),
		}, nil
	}

	supplier := NewCachedResultSupplier(refreshFunc, enums.StaleValueBehaviorRefresh)
	supplier.clock = mock

	result1, _ := supplier.Get()
	if result1.Value != "v1" {
		t.Fatalf("first value = %q, want %q", result1.Value, "v1")
	}

	// 推进到 stale 阶段
	mock.SetTime(result1.ExpiresAt.Add(-6 * time.Minute))

	result2, _ := supplier.Get()
	if result2.Value != "v2" {
		t.Errorf("stale Refresh should return new value %q, got %q", "v2", result2.Value)
	}
	if callCount != 2 {
		t.Errorf("callCount = %d, want 2", callCount)
	}
}

// TestGetWithContext_Stale_RefreshFail stale + Refresh 且刷新失败 → 返回旧值（nil error）。
func TestGetWithContext_Stale_RefreshFail(t *testing.T) {
	mock := NewMockClock(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))

	supplier := NewCachedResultSupplier(
		func(_ context.Context) (*RefreshResult[string], error) {
			return &RefreshResult[string]{
				Value:     "cached",
				ExpiresAt: mock.Now().Add(1 * time.Hour),
			}, nil
		},
		enums.StaleValueBehaviorRefresh,
	)
	supplier.clock = mock

	result1, _ := supplier.Get()
	if result1.Value != "cached" {
		t.Fatalf("first value = %q, want %q", result1.Value, "cached")
	}

	// 推进到 stale 阶段
	mock.SetTime(result1.ExpiresAt.Add(-6 * time.Minute))

	// 换成失败的 refreshFunc
	supplier.refreshFunc = func(_ context.Context) (*RefreshResult[string], error) {
		return nil, errors.New("refresh failed")
	}

	result2, err := supplier.GetWithContext(context.Background())
	if err != nil {
		t.Errorf("stale Refresh-fail should return nil error, got %v", err)
	}
	if result2 == nil || result2.Value != "cached" {
		t.Errorf("stale Refresh-fail should return cached value, got %v", result2)
	}
}

// TestGetWithContext_Expired_RefreshFail expired + Refresh 且刷新失败 → 返回旧值 + ErrStaleCredentialReturned。
func TestGetWithContext_Expired_RefreshFail(t *testing.T) {
	mock := NewMockClock(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))

	refreshFunc := func(_ context.Context) (*RefreshResult[string], error) {
		return nil, errors.New("refresh failed")
	}

	supplier := NewCachedResultSupplier(refreshFunc, enums.StaleValueBehaviorRefresh)
	supplier.clock = mock

	// 用一个成功的 refreshFunc 建立初始缓存
	supplier.refreshFunc = func(_ context.Context) (*RefreshResult[string], error) {
		return &RefreshResult[string]{
			Value:     "cached",
			ExpiresAt: mock.Now().Add(1 * time.Hour),
		}, nil
	}
	result1, _ := supplier.Get()
	if result1.Value != "cached" {
		t.Fatalf("first value = %q, want %q", result1.Value, "cached")
	}

	// 推进到已过期
	mock.SetTime(result1.ExpiresAt.Add(1 * time.Minute))

	// 换回失败的 refreshFunc
	supplier.refreshFunc = refreshFunc

	result2, err := supplier.GetWithContext(context.Background())
	if result2 == nil || result2.Value != "cached" {
		t.Errorf("expired Refresh-fail should return cached value, got %v", result2)
	}
	if err == nil {
		t.Error("expired Refresh-fail should return ErrStaleCredentialReturned")
	}
}

// TestNewRefreshResult_JitterInvariantsAcrossTTLs 是 M6/M13 要求的 jitter 不变量综合测试:
// 对 E ∈ {60,300,900,1800,3000,7200}s 各采样 10000 次,断言三条不变量:
//
//	① StaleTime / PrefetchTime 恒落在 [base, max(base, ceiling)] 内。ceiling = expiresAt-SafetyMargin。
//	   当 base 已超过 ceiling(极短 TTL,E=60s 时 60/5=12s < 30s SafetyMargin)时,
//	   jitter 区间收缩直接返回 base(无法回到过去),故上界取 max(base, ceiling)。
//	② ceiling-base > 0 时 StaleTime 取值个数 > 1(未退化为钳位常量,防惊群);
//	③ PrefetchTime < StaleTime 恒成立(prefetch-before-stale 设计意图)。
//
// 第 ③ 条是独立 jitter 写法在短/中 TTL 下会失败的那条 —— 收紧 PrefetchTime 的 jitter
// 上界到 StaleTime 后必须通过。E=3600(既有单点测试用的安全区)不在采样集,因其
// lo=JitterStart 保住、本就不会倒置;此处专挑会触发 lo 塌缩的短/中 TTL 与对照长 TTL。
func TestNewRefreshResult_JitterInvariantsAcrossTTLs(t *testing.T) {
	const samples = 10000
	base := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	mock := NewMockClock(base)
	SetClock(mock)
	defer SetClock(&SystemClock{})

	ttls := []int64{60, 300, 900, 1800, 3000, 7200}
	for _, expiresIn := range ttls {
		t.Run(fmtTTL(expiresIn), func(t *testing.T) {
			expiresInDur := time.Duration(expiresIn) * time.Second
			expiresAt := base.Add(expiresInDur)
			baseStale := expiresAt.Add(-expiresInDur / 5)
			basePrefetch := expiresAt.Add(-expiresInDur / 3)
			ceiling := expiresAt.Add(-SafetyMargin)
			staleUpper := baseStale
			if ceiling.After(staleUpper) {
				staleUpper = ceiling
			}
			prefetchUpper := basePrefetch
			if ceiling.After(prefetchUpper) {
				prefetchUpper = ceiling
			}

			seenStale := make(map[time.Time]struct{}, samples)
			roomStale := ceiling.Sub(baseStale)
			var maxPrefetch, minStale time.Time
			minStale = expiresAt
			inversion := 0

			for i := 0; i < samples; i++ {
				r, err := NewRefreshResult("v", base, expiresIn)
				if err != nil {
					t.Fatalf("sample %d: NewRefreshResult error: %v", i, err)
				}
				// ① 边界不变量:t ≤ result ≤ max(t, ceiling)
				if r.StaleTime.Before(baseStale) {
					t.Fatalf("sample %d: StaleTime %v before base %v", i, r.StaleTime, baseStale)
				}
				if r.StaleTime.After(staleUpper) {
					t.Fatalf("sample %d: StaleTime %v after upper %v", i, r.StaleTime, staleUpper)
				}
				if r.PrefetchTime.Before(basePrefetch) {
					t.Fatalf("sample %d: PrefetchTime %v before base %v", i, r.PrefetchTime, basePrefetch)
				}
				if r.PrefetchTime.After(prefetchUpper) {
					t.Fatalf("sample %d: PrefetchTime %v after upper %v", i, r.PrefetchTime, prefetchUpper)
				}
				// ③ prefetch-before-stale 不变量(本次修复目标)
				if !r.PrefetchTime.Before(r.StaleTime) {
					inversion++
				}
				seenStale[r.StaleTime] = struct{}{}
				if r.PrefetchTime.After(maxPrefetch) {
					maxPrefetch = r.PrefetchTime
				}
				if r.StaleTime.Before(minStale) {
					minStale = r.StaleTime
				}
			}
			// ③ 汇总
			if inversion > 0 {
				t.Fatalf("E=%ds: %d/%d samples had PrefetchTime >= StaleTime (inversion)", expiresIn, inversion, samples)
			}
			// ② 非退化:有随机空间时取值个数必须 > 1(防钳位退化为常量 → 惊群)
			if roomStale > 0 && len(seenStale) <= 1 {
				t.Fatalf("E=%ds: StaleTime produced only %d distinct value(s) over %d samples (room=%v), jitter degenerated to constant",
					expiresIn, len(seenStale), samples, roomStale)
			}
			t.Logf("E=%ds: distinct stale=%d, minStale=%v maxPrefetch=%v (roomStale=%v)",
				expiresIn, len(seenStale), minStale.Sub(base), maxPrefetch.Sub(base), roomStale)
		})
	}
}

// fmtTTL 把秒数格式化为测试子用例名(如 300s)。
func fmtTTL(secs int64) string {
	return strconv.FormatInt(secs, 10) + "s"
}
