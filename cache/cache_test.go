package cache

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
)

// ==================== Clock 测试 ====================

// TestSystemClock_Now 测试 SystemClock 的 Now 方法
func TestSystemClock_Now(t *testing.T) {
	clock := &SystemClock{}

	now := clock.Now()

	// 验证返回的时间接近当前时间
	expected := time.Now()
	diff := now.Sub(expected)
	if diff < -time.Second || diff > time.Second {
		t.Errorf("SystemClock.Now() 返回的时间与当前时间差异过大: %v", diff)
	}
}

// TestSystemClock_MultipleCalls 测试多次调用 Now 返回不同时间
func TestSystemClock_MultipleCalls(t *testing.T) {
	clock := &SystemClock{}

	time1 := clock.Now()
	time.Sleep(10 * time.Millisecond)
	time2 := clock.Now()

	if !time2.After(time1) {
		t.Error("第二次调用 Now() 应该晚于第一次")
	}
}

// ==================== Mock Clock 用于测试 ====================

// MockClock 模拟时钟，用于测试
type MockClock struct {
	currentTime time.Time
	mu          sync.Mutex
}

func NewMockClock(t time.Time) *MockClock {
	return &MockClock{currentTime: t}
}

func (c *MockClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.currentTime
}

func (c *MockClock) SetTime(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.currentTime = t
}

func (c *MockClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.currentTime = c.currentTime.Add(d)
}

// ==================== RefreshResult 测试 ====================

// TestRefreshResult_IsExpired_NotExpired 测试未过期的情况
func TestRefreshResult_IsExpired_NotExpired(t *testing.T) {
	future := time.Now().Add(1 * time.Hour)
	result := &RefreshResult[string]{
		Value:     "test",
		ExpiresAt: future,
		Error:     nil,
	}

	if result.IsExpired() {
		t.Error("未来过期的结果不应该被标记为已过期")
	}
}

// TestRefreshResult_IsExpired_Expired 测试已过期的情况
func TestRefreshResult_IsExpired_Expired(t *testing.T) {
	past := time.Now().Add(-1 * time.Hour)
	result := &RefreshResult[string]{
		Value:     "test",
		ExpiresAt: past,
		Error:     nil,
	}

	if !result.IsExpired() {
		t.Error("过去过期的结果应该被标记为已过期")
	}
}

// TestRefreshResult_IsExpired_ExactlyNow 测试刚好到期的情况
func TestRefreshResult_IsExpired_ExactlyNow(t *testing.T) {
	now := time.Now()
	result := &RefreshResult[string]{
		Value:     "test",
		ExpiresAt: now,
		Error:     nil,
	}

	// 由于时间精度，可能需要稍微等待
	time.Sleep(1 * time.Millisecond)
	if !result.IsExpired() {
		t.Error("刚好到期的结果应该被标记为已过期")
	}
}

// TestRefreshResult_WillSoonExpire_NotSoon 测试不即将过期的情况
func TestRefreshResult_WillSoonExpire_NotSoon(t *testing.T) {
	future := time.Now().Add(1 * time.Hour)
	result := &RefreshResult[string]{
		Value:     "test",
		ExpiresAt: future,
		Error:     nil,
	}

	threshold := 5 * time.Minute
	if result.WillSoonExpire(threshold) {
		t.Error("距离过期还很远的结果不应该被标记为即将过期")
	}
}

// TestRefreshResult_WillSoonExpire_Soon 测试即将过期的情况
func TestRefreshResult_WillSoonExpire_Soon(t *testing.T) {
	// 设置过期时间为 2 分钟后
	future := time.Now().Add(2 * time.Minute)
	result := &RefreshResult[string]{
		Value:     "test",
		ExpiresAt: future,
		Error:     nil,
	}

	threshold := 5 * time.Minute
	if !result.WillSoonExpire(threshold) {
		t.Error("在阈值内即将过期的结果应该被标记为即将过期")
	}
}

// TestRefreshResult_WillSoonExpire_AlreadyExpired 测试已过期但检查即将过期的情况
func TestRefreshResult_WillSoonExpire_AlreadyExpired(t *testing.T) {
	past := time.Now().Add(-1 * time.Hour)
	result := &RefreshResult[string]{
		Value:     "test",
		ExpiresAt: past,
		Error:     nil,
	}

	threshold := 5 * time.Minute
	// 已过期的也应该返回 true（因为 now + threshold 肯定在 expiresAt 之后）
	if !result.WillSoonExpire(threshold) {
		t.Error("已过期的结果在 WillSoonExpire 检查中应该返回 true")
	}
}

// TestRefreshResult_WithDifferentTypes 测试不同泛型类型
func TestRefreshResult_WithDifferentTypes(t *testing.T) {
	// 测试 int 类型
	intResult := &RefreshResult[int]{
		Value:     42,
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Error:     nil,
	}
	if intResult.Value != 42 {
		t.Errorf("int 类型值错误: 期望 42, 得到 %d", intResult.Value)
	}

	// 测试 struct 类型
	type TestData struct {
		Name string
		Age  int
	}
	structResult := &RefreshResult[TestData]{
		Value:     TestData{Name: "test", Age: 25},
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Error:     nil,
	}
	if structResult.Value.Name != "test" || structResult.Value.Age != 25 {
		t.Errorf("struct 类型值错误: %+v", structResult.Value)
	}
}

// TestRefreshResult_WithError 测试带错误的结果
func TestRefreshResult_WithError(t *testing.T) {
	testErr := errors.New("test error")
	result := &RefreshResult[string]{
		Value:     "",
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Error:     testErr,
	}

	if result.Error == nil {
		t.Error("期望有错误，但得到 nil")
	}
	if result.Error.Error() != "test error" {
		t.Errorf("错误消息不匹配: 期望 'test error', 得到 '%s'", result.Error.Error())
	}
}

// ==================== CachedResultSupplier 测试 ====================

// TestNewCachedResultSupplier 测试创建 CachedResultSupplier
func TestNewCachedResultSupplier(t *testing.T) {
	refreshFunc := func() (*RefreshResult[string], error) {
		return &RefreshResult[string]{
			Value:     "test",
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}, nil
	}

	supplier := NewCachedResultSupplier(
		refreshFunc,
		enums.StaleValueBehaviorBlock,
		5*time.Minute,
	)

	if supplier == nil {
		t.Fatal("NewCachedResultSupplier 返回 nil")
	}
	if supplier.refreshFunc == nil {
		t.Error("refreshFunc 未正确设置")
	}
	if supplier.staleBehavior != enums.StaleValueBehaviorBlock {
		t.Errorf("staleBehavior 不匹配: 期望 %s, 得到 %s",
			enums.StaleValueBehaviorBlock, supplier.staleBehavior)
	}
	if supplier.prefetchThreshold != 5*time.Minute {
		t.Errorf("prefetchThreshold 不匹配: 期望 %v, 得到 %v",
			5*time.Minute, supplier.prefetchThreshold)
	}
	if supplier.clock == nil {
		t.Error("clock 未正确初始化")
	}
}

// TestCachedResultSupplier_Get_NoCache 测试没有缓存时的获取
func TestCachedResultSupplier_Get_NoCache(t *testing.T) {
	callCount := 0
	refreshFunc := func() (*RefreshResult[string], error) {
		callCount++
		return &RefreshResult[string]{
			Value:     "fresh-value",
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}, nil
	}

	supplier := NewCachedResultSupplier(
		refreshFunc,
		enums.StaleValueBehaviorBlock,
		5*time.Minute,
	)

	result, err := supplier.Get()

	if err != nil {
		t.Fatalf("Get() 返回错误: %v", err)
	}
	if result.Value != "fresh-value" {
		t.Errorf("值不匹配: 期望 'fresh-value', 得到 '%s'", result.Value)
	}
	if callCount != 1 {
		t.Errorf("refreshFunc 应该被调用 1 次，实际调用 %d 次", callCount)
	}
}

// TestCachedResultSupplier_Get_CacheHit 测试缓存命中
func TestCachedResultSupplier_Get_CacheHit(t *testing.T) {
	callCount := 0
	refreshFunc := func() (*RefreshResult[string], error) {
		callCount++
		return &RefreshResult[string]{
			Value:     "cached-value",
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}, nil
	}

	supplier := NewCachedResultSupplier(
		refreshFunc,
		enums.StaleValueBehaviorBlock,
		5*time.Minute,
	)

	// 第一次调用，建立缓存
	result1, err := supplier.Get()
	if err != nil {
		t.Fatalf("第一次 Get() 返回错误: %v", err)
	}

	// 第二次调用，应该使用缓存
	result2, err := supplier.Get()
	if err != nil {
		t.Fatalf("第二次 Get() 返回错误: %v", err)
	}

	if result1.Value != result2.Value {
		t.Error("两次调用应该返回相同的缓存值")
	}
	if callCount != 1 {
		t.Errorf("refreshFunc 应该只被调用 1 次，实际调用 %d 次", callCount)
	}
}

// TestCachedResultSupplier_Get_Expired_Block 测试过期时阻塞刷新
func TestCachedResultSupplier_Get_Expired_Block(t *testing.T) {
	callCount := 0
	var mu sync.Mutex

	refreshFunc := func() (*RefreshResult[string], error) {
		mu.Lock()
		defer mu.Unlock()
		callCount++
		value := fmt.Sprintf("value-%d", callCount)
		return &RefreshResult[string]{
			Value:     value,
			ExpiresAt: time.Now().Add(50 * time.Millisecond), // 很短的过期时间
		}, nil
	}

	supplier := NewCachedResultSupplier(
		refreshFunc,
		enums.StaleValueBehaviorBlock,
		5*time.Minute,
	)

	// 第一次调用，建立缓存
	result1, _ := supplier.Get()
	if result1.Value != "value-1" {
		t.Errorf("第一次调用值错误: 期望 'value-1', 得到 '%s'", result1.Value)
	}

	// 等待缓存过期
	time.Sleep(100 * time.Millisecond)

	// 第二次调用，应该触发阻塞刷新
	result2, _ := supplier.Get()

	mu.Lock()
	finalCallCount := callCount
	mu.Unlock()

	if finalCallCount < 2 {
		t.Errorf("过期后应该触发刷新，总调用次数至少为 2，实际为 %d", finalCallCount)
	}
	_ = result2
}

// TestCachedResultSupplier_Get_Expired_Allow 测试过期时允许返回旧值并异步刷新
func TestCachedResultSupplier_Get_Expired_Allow(t *testing.T) {
	callCount := 0
	var mu sync.Mutex

	refreshFunc := func() (*RefreshResult[string], error) {
		mu.Lock()
		defer mu.Unlock()
		callCount++
		value := fmt.Sprintf("value-%d", callCount)
		return &RefreshResult[string]{
			Value:     value,
			ExpiresAt: time.Now().Add(50 * time.Millisecond), // 很短的过期时间
		}, nil
	}

	supplier := NewCachedResultSupplier(
		refreshFunc,
		enums.StaleValueBehaviorAllow,
		5*time.Minute,
	)

	// 第一次调用，建立缓存
	result1, _ := supplier.Get()
	if result1.Value != "value-1" {
		t.Errorf("第一次调用值错误: 期望 'value-1', 得到 '%s'", result1.Value)
	}

	// 等待缓存过期
	time.Sleep(100 * time.Millisecond)

	// 第二次调用，应该返回过期值并异步刷新
	result2, _ := supplier.Get()
	if result2.Value != "value-1" {
		t.Errorf("ALLOW 模式下，过期时应该返回旧值: 期望 'value-1', 得到 '%s'", result2.Value)
	}

	// 等待异步刷新完成
	time.Sleep(150 * time.Millisecond)

	// 第三次调用，应该得到新值
	result3, _ := supplier.Get()

	mu.Lock()
	finalCallCount := callCount
	mu.Unlock()

	if finalCallCount < 2 {
		t.Errorf("异步刷新应该被触发，总调用次数至少为 2，实际为 %d", finalCallCount)
	}
	_ = result3
}

// TestCachedResultSupplier_Get_Expired_Refresh 测试过期时同步刷新
func TestCachedResultSupplier_Get_Expired_Refresh(t *testing.T) {
	callCount := 0
	var mu sync.Mutex

	refreshFunc := func() (*RefreshResult[string], error) {
		mu.Lock()
		defer mu.Unlock()
		callCount++
		value := fmt.Sprintf("value-%d", callCount)
		return &RefreshResult[string]{
			Value:     value,
			ExpiresAt: time.Now().Add(50 * time.Millisecond), // 很短的过期时间
		}, nil
	}

	supplier := NewCachedResultSupplier(
		refreshFunc,
		enums.StaleValueBehaviorRefresh,
		5*time.Minute,
	)

	// 第一次调用，建立缓存
	result1, _ := supplier.Get()
	if result1.Value != "value-1" {
		t.Errorf("第一次调用值错误: 期望 'value-1', 得到 '%s'", result1.Value)
	}

	// 等待缓存过期
	time.Sleep(100 * time.Millisecond)

	// 第二次调用，应该同步刷新并返回新值
	result2, _ := supplier.Get()

	mu.Lock()
	finalCallCount := callCount
	mu.Unlock()

	if finalCallCount < 2 {
		t.Errorf("REFRESH 模式下，过期时应该触发刷新，总调用次数至少为 2，实际为 %d", finalCallCount)
	}
	_ = result2
}

// TestCachedResultSupplier_Get_Prefetch 测试预取功能
func TestCachedResultSupplier_Get_Prefetch(t *testing.T) {
	callCount := 0
	var mu sync.Mutex

	refreshFunc := func() (*RefreshResult[string], error) {
		mu.Lock()
		defer mu.Unlock()
		callCount++
		value := fmt.Sprintf("value-%d", callCount)
		return &RefreshResult[string]{
			Value:     value,
			ExpiresAt: time.Now().Add(200 * time.Millisecond), // 较短的过期时间
		}, nil
	}

	supplier := NewCachedResultSupplier(
		refreshFunc,
		enums.StaleValueBehaviorBlock,
		150*time.Millisecond, // 预取阈值：150毫秒
	)

	// 第一次调用，建立缓存（过期时间 200 毫秒后）
	result1, _ := supplier.Get()
	if result1.Value != "value-1" {
		t.Errorf("第一次调用值错误: 期望 'value-1', 得到 '%s'", result1.Value)
	}

	// 等待 60 毫秒（剩余 140 毫秒，小于阈值 150 毫秒，应该触发预取）
	time.Sleep(60 * time.Millisecond)

	// 调用 Get，应该触发异步预取
	result2, _ := supplier.Get()
	if result2.Value != "value-1" {
		t.Errorf("预取时应该返回旧值: 期望 'value-1', 得到 '%s'", result2.Value)
	}

	// 等待异步预取完成
	time.Sleep(150 * time.Millisecond)

	mu.Lock()
	finalCallCount := callCount
	mu.Unlock()

	if finalCallCount < 2 {
		t.Errorf("预取应该触发刷新，总调用次数至少为 2，实际为 %d", finalCallCount)
	}
}

// TestCachedResultSupplier_Invalidate 测试缓存失效
func TestCachedResultSupplier_Invalidate(t *testing.T) {
	callCount := 0
	refreshFunc := func() (*RefreshResult[string], error) {
		callCount++
		return &RefreshResult[string]{
			Value:     fmt.Sprintf("value-%d", callCount),
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}, nil
	}

	supplier := NewCachedResultSupplier(
		refreshFunc,
		enums.StaleValueBehaviorBlock,
		5*time.Minute,
	)

	// 第一次调用，建立缓存
	result1, _ := supplier.Get()
	if result1.Value != "value-1" {
		t.Errorf("第一次调用值错误")
	}

	// 使缓存失效
	supplier.Invalidate()

	// 第二次调用，应该重新刷新
	result2, _ := supplier.Get()
	if result2.Value != "value-2" {
		t.Errorf("缓存失效后应该重新刷新: 期望 'value-2', 得到 '%s'", result2.Value)
	}
	if callCount != 2 {
		t.Errorf("refreshFunc 应该被调用 2 次，实际调用 %d 次", callCount)
	}
}

// TestCachedResultSupplier_RefreshError 测试刷新失败的情况
func TestCachedResultSupplier_RefreshError(t *testing.T) {
	refreshFunc := func() (*RefreshResult[string], error) {
		return nil, errors.New("refresh failed")
	}

	supplier := NewCachedResultSupplier(
		refreshFunc,
		enums.StaleValueBehaviorBlock,
		5*time.Minute,
	)

	result, err := supplier.Get()

	if err == nil {
		t.Error("期望返回错误，但得到 nil")
	}
	if result != nil {
		t.Error("出错时期望返回 nil 结果")
	}
}

// TestCachedResultSupplier_ConcurrentAccess 测试并发访问
func TestCachedResultSupplier_ConcurrentAccess(t *testing.T) {
	callCount := 0
	var mu sync.Mutex
	refreshFunc := func() (*RefreshResult[string], error) {
		mu.Lock()
		defer mu.Unlock()
		callCount++
		return &RefreshResult[string]{
			Value:     "concurrent-value",
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}, nil
	}

	supplier := NewCachedResultSupplier(
		refreshFunc,
		enums.StaleValueBehaviorBlock,
		5*time.Minute,
	)

	// 并发调用 Get
	var wg sync.WaitGroup
	numGoroutines := 10
	results := make([]*RefreshResult[string], numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			result, err := supplier.Get()
			if err != nil {
				t.Errorf("supplier.Get() failed: %v", err)
				return
			}
			results[idx] = result
		}(i)
	}

	wg.Wait()

	// 验证所有结果都相同
	for i := 1; i < numGoroutines; i++ {
		if results[i].Value != results[0].Value {
			t.Errorf("并发访问时结果不一致: results[%d]=%s, results[0]=%s",
				i, results[i].Value, results[0].Value)
		}
	}

	// refreshFunc 应该只被调用一次（或少数几次，取决于并发竞争）
	mu.Lock()
	finalCallCount := callCount
	mu.Unlock()

	if finalCallCount > 3 {
		t.Errorf("并发访问时 refreshFunc 被调用太多次: %d 次", finalCallCount)
	}
}

// TestCachedResultSupplier_WithMockClock 测试使用模拟时钟
func TestCachedResultSupplier_WithMockClock(t *testing.T) {
	baseTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	mockClock := NewMockClock(baseTime)

	refreshFunc := func() (*RefreshResult[string], error) {
		return &RefreshResult[string]{
			Value:     "test",
			ExpiresAt: mockClock.Now().Add(10 * time.Minute),
		}, nil
	}

	supplier := NewCachedResultSupplier(
		refreshFunc,
		enums.StaleValueBehaviorBlock,
		5*time.Minute,
	)
	supplier.clock = mockClock

	// 第一次调用
	result1, _ := supplier.Get()
	if result1.Value != "test" {
		t.Errorf("第一次调用值错误")
	}

	// 推进时间但不超过过期时间
	mockClock.Advance(5 * time.Minute)

	// 第二次调用，应该使用缓存
	result2, _ := supplier.Get()
	if result2.Value != "test" {
		t.Errorf("第二次调用应该使用缓存")
	}
}

// ==================== singleflight + 锁外 IO 行为验证 ====================

// TestCachedResultSupplier_Singleflight_NoCache 验证缓存为空时 N 个并发调用方
// 只会触发 1 次 refreshFunc（singleflight 合并）。这是 Critical #1 修复的核心契约。
func TestCachedResultSupplier_Singleflight_NoCache(t *testing.T) {
	var callCount int32
	var refreshStarted, refreshDone sync.WaitGroup
	refreshStarted.Add(1)
	refreshDone.Add(1)

	refreshFunc := func() (*RefreshResult[string], error) {
		atomic.AddInt32(&callCount, 1)
		refreshStarted.Done() // 通知主测试：refresh 已经进入
		refreshDone.Wait()    // 阻塞，直到主测试放行
		return &RefreshResult[string]{
			Value:     "fresh",
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}, nil
	}

	supplier := NewCachedResultSupplier(refreshFunc, enums.StaleValueBehaviorBlock, 5*time.Minute)

	const numGoroutines = 50
	var wg sync.WaitGroup
	results := make([]*RefreshResult[string], numGoroutines)
	errs := make([]error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx], errs[idx] = supplier.Get()
		}(i)
	}

	// 等所有 goroutine 都进入 Get 并阻塞在 inflight done channel 上
	refreshStarted.Wait()
	time.Sleep(50 * time.Millisecond) // 让其他 49 个 goroutine 也进入等待
	refreshDone.Done()                // 放行 refreshFunc 返回

	wg.Wait()

	// 严格断言：50 个并发 Get 只触发 1 次 refreshFunc
	if got := atomic.LoadInt32(&callCount); got != 1 {
		t.Errorf("singleflight 失败：期望 refreshFunc 被调用 1 次，实际 %d 次", got)
	}

	// 所有 goroutine 必须拿到完全相同的结果
	for i := 0; i < numGoroutines; i++ {
		if errs[i] != nil {
			t.Errorf("goroutine[%d] 返回错误: %v", i, errs[i])
		}
		if results[i] == nil || results[i].Value != "fresh" {
			t.Errorf("goroutine[%d] 结果错误: %+v", i, results[i])
		}
	}
}

// TestCachedResultSupplier_LockFreeIO 验证 refreshFunc 不再持有 s.mu。
// 如果旧实现（持锁 IO）回归，那么在 refreshFunc 阻塞期间任何对 Get/Invalidate
// 的调用都会卡死；新实现下，Invalidate 必须能在 refreshFunc 阻塞期间立即返回。
func TestCachedResultSupplier_LockFreeIO(t *testing.T) {
	refreshStarted := make(chan struct{})
	refreshUnblock := make(chan struct{})

	refreshFunc := func() (*RefreshResult[string], error) {
		close(refreshStarted)
		<-refreshUnblock
		return &RefreshResult[string]{
			Value:     "v",
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}, nil
	}

	supplier := NewCachedResultSupplier(refreshFunc, enums.StaleValueBehaviorBlock, 5*time.Minute)

	go func() {
		_, _ = supplier.Get() // 触发 refreshFunc
	}()

	<-refreshStarted // 此时 refreshFunc 已经在跑

	// 关键断言：Invalidate 必须能立即返回，不被 refreshFunc 阻塞
	done := make(chan struct{})
	go func() {
		supplier.Invalidate()
		close(done)
	}()
	select {
	case <-done:
		// OK：Invalidate 在 refreshFunc 还没返回时就完成了，证明 IO 在锁外
	case <-time.After(500 * time.Millisecond):
		close(refreshUnblock) // 避免 goroutine 泄漏
		t.Fatal("Invalidate 被 refreshFunc 阻塞超过 500ms，回归到了持锁 IO")
	}

	close(refreshUnblock)
}

// TestCachedResultSupplier_Singleflight_DedupOnPrefetch 验证即将过期触发预取时
// 多次 Get 不会触发多次 refreshFunc 的异步刷新（去重）。
func TestCachedResultSupplier_Singleflight_DedupOnPrefetch(t *testing.T) {
	var callCount int32
	released := make(chan struct{})
	refreshFunc := func() (*RefreshResult[string], error) {
		n := atomic.AddInt32(&callCount, 1)
		if n > 1 {
			// 第二次及之后的 refresh：阻塞一会儿，便于上层并发 Get
			<-released
		}
		return &RefreshResult[string]{
			Value:     "v",
			ExpiresAt: time.Now().Add(200 * time.Millisecond),
		}, nil
	}

	supplier := NewCachedResultSupplier(refreshFunc, enums.StaleValueBehaviorBlock, 180*time.Millisecond)

	// 第一次：建缓存
	if _, err := supplier.Get(); err != nil {
		t.Fatalf("初次 Get 失败: %v", err)
	}

	// 此时缓存还有 ~200ms，prefetchThreshold 是 180ms，立刻就会触发异步预取
	// 连续触发 20 次 Get，去重后应该只多触发 1 次 refreshFunc
	for i := 0; i < 20; i++ {
		_, _ = supplier.Get()
	}

	time.Sleep(50 * time.Millisecond)
	close(released)
	time.Sleep(50 * time.Millisecond)

	got := atomic.LoadInt32(&callCount)
	if got > 2 {
		t.Errorf("预取去重失败：期望 refreshFunc 总调用 ≤ 2 次，实际 %d 次", got)
	}
}

// ==================== 辅助函数 ====================

// 注意：需要在文件顶部添加 import "fmt"
// 但由于这是测试文件，我们在需要时使用 fmt.Sprintf
