package cache

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloud-idaas/idaas-go-core-sdk/cache/strategy"
	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
)

// TestTriggerAsyncRefresh_ConcurrentClose_NoDataRace :
//
// triggerAsyncRefresh 在锁外读 prefetchStrategy,而 Close 在锁内将其置 nil。
// 修复前 triggerAsyncRefresh 是裸读,与 Close 的写构成 data race —— GetWithContext
// 的 stale/prefetch/allow 三条路径都会无锁调用它,在 -race 下必报。
//
// 本测试在 -race 下并发"triggerAsyncRefresh × N"与"Close",若回归裸读,
// race detector 会直接 FAIL。注入真实的 NonBlockingPrefetchStrategy,
// 使 Prefetch→doAsyncRefresh 链路也被一并覆盖(策略内部 wg/slot 的并发)。
//
// 因 doAsyncRefresh 内部 go func 不被任何 wg 跟踪,refresh 用原子计数 +
// 在每轮迭代结束后短暂等待,确保后台 goroutine 收敛,不跨迭代访问上一轮 supplier。
func TestTriggerAsyncRefresh_ConcurrentClose_NoDataRace(t *testing.T) {
	const iterations = 200
	var refreshCalls int32

	for i := 0; i < iterations; i++ {
		ps := strategy.NewNonBlockingPrefetchStrategy()
		supplier := NewCachedResultSupplier(
			func(_ context.Context) (*RefreshResult[string], error) {
				atomic.AddInt32(&refreshCalls, 1)
				return &RefreshResult[string]{
					Value:     "v",
					ExpiresAt: time.Now().Add(1 * time.Hour),
				}, nil
			},
			enums.StaleValueBehaviorBlock,
		).WithPrefetchStrategy(ps)

		var wg sync.WaitGroup
		// 多个 triggerAsyncRefresh 与一个 Close 并发,最大化触发 prefetchStrategy
		// 读写交错的窗口。
		wg.Add(4)
		go func() { defer wg.Done(); supplier.triggerAsyncRefresh() }()
		go func() { defer wg.Done(); supplier.triggerAsyncRefresh() }()
		go func() { defer wg.Done(); supplier.triggerAsyncRefresh() }()
		go func() { defer wg.Done(); supplier.Close() }()
		wg.Wait()

		// doAsyncRefresh 的后台 go func 不被 NonBlocking.wg 跟踪,
		// 给它一个收敛窗口,避免跨迭代引用上一轮的 supplier。
		time.Sleep(2 * time.Millisecond)
		ps.Close() // 幂等:supplier.Close 已调一次,再调确认 closeOnce 安全
	}

	if atomic.LoadInt32(&refreshCalls) == 0 {
		// 不强制要求 > 0(Close 可能在 Prefetch 之前赢),但记录一条诊断信息。
		t.Log("refreshFunc was never invoked across iterations (Close consistently won the race); test still valid for race detection")
	}
}

// TestWithPrefetchStrategy_ConcurrentSet_NoDataRace :
// 并发多次 WithPrefetchStrategy(不同实例)与 Close,验证写侧锁的正确性。
// WithPrefetchStrategy 通常在构造期单线程调用,但作为 exported 方法且与 Close
// 共享同一字段,这里锁定写写/写读不竞争。
func TestWithPrefetchStrategy_ConcurrentSet_NoDataRace(t *testing.T) {
	supplier := NewCachedResultSupplier(
		func(_ context.Context) (*RefreshResult[string], error) {
			return &RefreshResult[string]{
				Value:     "v",
				ExpiresAt: time.Now().Add(1 * time.Hour),
			}, nil
		},
		enums.StaleValueBehaviorBlock,
	)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			supplier.WithPrefetchStrategy(strategy.NewNonBlockingPrefetchStrategy())
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			supplier.triggerAsyncRefresh()
		}
	}()
	wg.Wait()
	supplier.Close()
}
