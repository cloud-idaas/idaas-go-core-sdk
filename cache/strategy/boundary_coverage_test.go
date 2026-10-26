package strategy

import (
	"sync/atomic"
	"testing"
	"time"
)

// TestBoundary_NonBlocking_PrefetchPanicRecover 验证 Prefetch 中 refresh() panic
// 被 recover 捕获，不崩溃，且信号槽被释放（后续 Prefetch 仍可正常执行）。
func TestBoundary_NonBlocking_PrefetchPanicRecover(t *testing.T) {
	s := NewNonBlockingPrefetchStrategy()
	defer s.Close()

	// 调用 Prefetch 传入一个会 panic 的 refresh 函数
	s.Prefetch(func() {
		panic("test panic")
	})

	// 等待 goroutine 执行完毕（recover 应捕获 panic）
	time.Sleep(100 * time.Millisecond)

	// 验证信号槽被释放：后续 Prefetch 仍可正常执行
	var called int32
	s.Prefetch(func() {
		atomic.AddInt32(&called, 1)
	})

	// 等待第二次 refresh 执行
	time.Sleep(100 * time.Millisecond)

	if got := atomic.LoadInt32(&called); got != 1 {
		t.Errorf("after panic recovery, expected signal slot freed and second refresh to execute, callCount=%d", got)
	}
}
