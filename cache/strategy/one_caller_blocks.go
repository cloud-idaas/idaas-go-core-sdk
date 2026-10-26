package strategy

import (
	"sync"
	"sync/atomic"
)

// OneCallerBlocksPrefetchStrategy 单调用者阻塞预取策略。
//
// 仅第一个调用者执行 refresh，其余直接返回（与 Java AtomicBoolean / Python threading.Event 对齐）。
// 保留 sync.Once 幂等关闭设计。
type OneCallerBlocksPrefetchStrategy struct {
	closeOnce  sync.Once
	closedFlag int32 // 0=open, 1=closed；atomic 读写使 Close() 对 Prefetch() 可见
	running    int32 // 0=idle, 1=running；CAS 守卫确保仅一个调用者执行 refresh
}

// NewOneCallerBlocksPrefetchStrategy 创建单调用者阻塞预取策略。
func NewOneCallerBlocksPrefetchStrategy() *OneCallerBlocksPrefetchStrategy {
	return &OneCallerBlocksPrefetchStrategy{}
}

// Prefetch 仅第一个调用者同步执行 refresh，其余直接返回(对齐 Java/Python 去重语义)。
//
// 使用 atomic.CompareAndSwapInt32 而非 atomic.Bool（后者需 Go 1.19，
// 本 SDK 锁定 Go 1.18 下限）。
func (s *OneCallerBlocksPrefetchStrategy) Prefetch(refresh func()) {
	// Close() 后不再接受新的 prefetch 请求。
	if atomic.LoadInt32(&s.closedFlag) != 0 {
		return
	}
	if !atomic.CompareAndSwapInt32(&s.running, 0, 1) {
		return // 已有调用者在执行，直接返回
	}
	defer atomic.StoreInt32(&s.running, 0)
	refresh()
}

// Close 释放资源（幂等）。
func (s *OneCallerBlocksPrefetchStrategy) Close() error {
	s.closeOnce.Do(func() {
		atomic.StoreInt32(&s.closedFlag, 1)
	})
	return nil
}
