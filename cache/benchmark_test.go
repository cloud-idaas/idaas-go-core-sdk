package cache

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
)

// BenchmarkGetWithContextCacheHit measures the hot path: cache hit with valid
// (non-expired) result, no refresh triggered.
//
// This is the most performance-critical path — every credential request hits it
// after the first refresh. The RWMutex read lock  ensures reads don't
// serialize behind writes.
func BenchmarkGetWithContextCacheHit(b *testing.B) {
	refreshFunc := func(context.Context) (*RefreshResult[string], error) {
		// 用 NewRefreshResult 构造，使 StaleTime/PrefetchTime 被正确计算。
		// 原实现直接构造 RefreshResult{Value, ExpiresAt}，StaleTime/PrefetchTime 为零值，
		// 导致每次 GetWithContext 都命中 stale 路径(StaleValueBehaviorBlock → doRefresh)，
		// benchmark 实际测的是"每次同步刷新"而非"缓存命中热路径"。
		result, err := NewRefreshResult("cached", time.Now(), 3600)
		if err != nil {
			b.Fatalf("new refresh result: %v", err)
		}
		return &result, nil
	}
	supplier := NewCachedResultSupplier(refreshFunc, enums.StaleValueBehaviorBlock)

	// Prime the cache
	if _, err := supplier.GetWithContext(context.Background()); err != nil {
		b.Fatalf("prime failed: %v", err)
	}

	ctx := context.Background()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = supplier.GetWithContext(ctx)
	}
}

// BenchmarkGetWithContextCacheMiss measures the cold path: no cache, each call
// triggers a synchronous refresh.
func BenchmarkGetWithContextCacheMiss(b *testing.B) {
	var count int64
	refreshFunc := func(context.Context) (*RefreshResult[string], error) {
		atomic.AddInt64(&count, 1)
		// 同样用 NewRefreshResult，保证与 CacheHit 构造口径一致，
		// 使两条 benchmark 的差异只来自缓存命中/未命中，而非构造路径不同。
		result, err := NewRefreshResult("fresh", time.Now(), 3600)
		if err != nil {
			b.Fatalf("new refresh result: %v", err)
		}
		return &result, nil
	}

	ctx := context.Background()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		// Each iteration uses a fresh supplier → guaranteed cache miss
		supplier := NewCachedResultSupplier(refreshFunc, enums.StaleValueBehaviorBlock)
		_, _ = supplier.GetWithContext(ctx)
	}
}

// BenchmarkConcurrentGet measures concurrent cache hits with high contention.
// Validates that singleflight + RWMutex allow parallel reads without serialization.
func BenchmarkConcurrentGet(b *testing.B) {
	refreshFunc := func(context.Context) (*RefreshResult[string], error) {
		// 用 NewRefreshResult，避免零值 StaleTime/PrefetchTime 把并发读退化成同步刷新。
		result, err := NewRefreshResult("cached", time.Now(), 3600)
		if err != nil {
			b.Fatalf("new refresh result: %v", err)
		}
		return &result, nil
	}
	supplier := NewCachedResultSupplier(refreshFunc, enums.StaleValueBehaviorBlock)

	// Prime the cache
	if _, err := supplier.Get(); err != nil {
		b.Fatalf("prime failed: %v", err)
	}

	ctx := context.Background()
	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = supplier.GetWithContext(ctx)
		}
	})
}

// BenchmarkNewRefreshResult measures the construction cost of a RefreshResult
// including StaleTime/PrefetchTime computation and jitter.
func BenchmarkNewRefreshResult(b *testing.B) {
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = NewRefreshResult[string](fmt.Sprintf("val-%d", i), time.Now(), 3600)
	}
}
