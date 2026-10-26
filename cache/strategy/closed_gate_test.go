package strategy

import (
	"sync/atomic"
	"testing"
	"time"
)

// TestNonBlocking_PrefetchAfterClose_Noop :
// Close 之后 Prefetch 必须是 no-op,不再启动新的后台 goroutine。
// 修复前 done 通道是死代码、Prefetch 无 closed 门禁,Close 后仍可经 refreshSlot 启 goroutine。
func TestNonBlocking_PrefetchAfterClose_Noop(t *testing.T) {
	s := NewNonBlockingPrefetchStrategy()
	s.Close()

	var called int32
	for i := 0; i < 10; i++ {
		s.Prefetch(func() { atomic.AddInt32(&called, 1) })
	}
	time.Sleep(50 * time.Millisecond)
	if got := atomic.LoadInt32(&called); got != 0 {
		t.Errorf("Prefetch after Close must be no-op, got %d invocations", got)
	}
}

// TestNonBlocking_CloseWaitsForInFlightThenNoLeak :
// Close 必须等待在飞 goroutine 完成,返回后新 Prefetch 不再泄漏 goroutine。
func TestNonBlocking_CloseWaitsForInFlightThenNoLeak(t *testing.T) {
	s := NewNonBlockingPrefetchStrategy()
	started := make(chan struct{})
	block := make(chan struct{})
	s.Prefetch(func() {
		close(started)
		<-block
	})
	<-started

	closeReturned := make(chan struct{})
	go func() { s.Close(); close(closeReturned) }()
	// Close 应阻塞,因为 in-flight refresh 未结束。
	select {
	case <-closeReturned:
		t.Fatal("Close returned before in-flight refresh finished")
	case <-time.After(50 * time.Millisecond):
	}

	close(block) // 放行 in-flight
	select {
	case <-closeReturned:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not return after in-flight finished")
	}

	// Close 返回后,新 Prefetch 必须是 no-op,不泄漏 goroutine。
	var called int32
	s.Prefetch(func() { atomic.AddInt32(&called, 1) })
	time.Sleep(50 * time.Millisecond)
	if got := atomic.LoadInt32(&called); got != 0 {
		t.Errorf("Prefetch after Close leaked a goroutine: %d calls", got)
	}
}

// TestOneCallerBlocks_PrefetchAfterClose_Noop :
// OneCallerBlocks 本就有 closedFlag 守卫,此处确认行为一致,避免回归。
func TestOneCallerBlocks_PrefetchAfterClose_Noop(t *testing.T) {
	s := NewOneCallerBlocksPrefetchStrategy()
	s.Close()

	var called int32
	s.Prefetch(func() { atomic.AddInt32(&called, 1) })
	if got := atomic.LoadInt32(&called); got != 0 {
		t.Errorf("Prefetch after Close must be no-op, got %d invocations", got)
	}
}
