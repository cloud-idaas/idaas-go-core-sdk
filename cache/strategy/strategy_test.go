package strategy

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestPrefetchStrategy_Interface 验证两个策略都实现 PrefetchStrategy 接口
func TestPrefetchStrategy_Interface(t *testing.T) {
	var _ PrefetchStrategy = (*NonBlockingPrefetchStrategy)(nil)
	var _ PrefetchStrategy = (*OneCallerBlocksPrefetchStrategy)(nil)
}

// TestOneCallerBlocks_Prefetch 验证同步执行 refresh
func TestOneCallerBlocks_Prefetch(t *testing.T) {
	s := NewOneCallerBlocksPrefetchStrategy()
	var called int32
	s.Prefetch(func() {
		atomic.AddInt32(&called, 1)
	})
	if atomic.LoadInt32(&called) != 1 {
		t.Errorf("expected 1 call, got %d", called)
	}
	s.Close()
}

// TestNonBlocking_Prefetch 验证异步执行 refresh
func TestNonBlocking_Prefetch(t *testing.T) {
	s := NewNonBlockingPrefetchStrategy()
	var called int32
	var wg sync.WaitGroup
	wg.Add(1)
	s.Prefetch(func() {
		atomic.AddInt32(&called, 1)
		wg.Done()
	})
	wg.Wait()
	if atomic.LoadInt32(&called) != 1 {
		t.Errorf("expected 1 call, got %d", called)
	}
	s.Close()
}

// TestNonBlocking_GoroutineLimit 验证 refreshSlot 限流
func TestNonBlocking_GoroutineLimit(t *testing.T) {
	s := NewNonBlockingPrefetchStrategy()
	var liveCount int32
	var maxLive int32
	var mu sync.Mutex

	refresh := func() {
		cur := atomic.AddInt32(&liveCount, 1)
		mu.Lock()
		if cur > maxLive {
			maxLive = cur
		}
		mu.Unlock()
		time.Sleep(50 * time.Millisecond)
		atomic.AddInt32(&liveCount, -1)
	}

	// 并发触发 10 次
	for i := 0; i < 10; i++ {
		s.Prefetch(refresh)
	}
	time.Sleep(200 * time.Millisecond)
	s.Close()

	mu.Lock()
	got := maxLive
	mu.Unlock()
	if got > 1 {
		t.Errorf("goroutine 限流失败：期望最多 1 个并发，实际 %d", got)
	}
}

// TestNonBlocking_CloseIdempotent 验证 Close 幂等
func TestNonBlocking_CloseIdempotent(t *testing.T) {
	s := NewNonBlockingPrefetchStrategy()
	s.Close()
	s.Close() // 不能 panic
}

// TestOneCallerBlocks_CloseIdempotent 验证 Close 幂等
func TestOneCallerBlocks_CloseIdempotent(t *testing.T) {
	s := NewOneCallerBlocksPrefetchStrategy()
	s.Close()
	s.Close()
}

// TestOneCallerBlocks_Dedup 验证并发场景下仅第一个调用者执行 refresh (F-03 修复)
func TestOneCallerBlocks_Dedup(t *testing.T) {
	s := NewOneCallerBlocksPrefetchStrategy()
	var called int32
	var wg sync.WaitGroup

	refresh := func() {
		atomic.AddInt32(&called, 1)
		time.Sleep(50 * time.Millisecond) // 模拟刷新耗时，让其他调用者命中 CAS 失败
	}

	// 并发触发 10 次
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.Prefetch(refresh)
		}()
	}
	wg.Wait()
	s.Close()

	got := atomic.LoadInt32(&called)
	if got != 1 {
		t.Errorf("dedup 失败：期望仅 1 次执行，实际 %d", got)
	}
}
