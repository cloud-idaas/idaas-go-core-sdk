package cache

import (
	"sync"
	"time"

	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
)

// CachedResultSupplier 缓存结果供应商 (§7.1)
//
// 设计要点（修正原实现的 3 个并发缺陷）：
//
//  1. 锁外 IO：refreshFunc（通常是 OAuth2 token endpoint HTTP 调用）必须在
//     不持有 s.mu 的情况下执行。旧实现在 refresh()/refreshAsync() 里
//     `s.mu.Lock(); defer s.mu.Unlock(); refreshFunc()`，导致一次 token endpoint
//     慢响应就让所有读者全部阻塞、且与 Invalidate/Get 互相死锁。
//
//  2. singleflight 合并：并发 N 个调用方在缓存缺失/过期时，只有一个会真正
//     执行 refreshFunc，其他全部等同一个 in-flight 任务的结果——既消除
//     thundering herd 把 IDaaS 打挂，也保证返回值一致。用 sync.Mutex
//     +ongoingRefresh 指针实现，无需引入 golang.org/x/sync/singleflight。
//
//  3. 异步预取去重：cached 即将过期时只允许一个 goroutine 在跑预取；
//     ongoingRefresh 已存在则直接跳过，避免 goroutine 堆积。
//
//  4. generation counter：防止 Invalidate() 后异步刷新结果覆盖已失效状态。
type CachedResultSupplier[T any] struct {
	mu                sync.Mutex
	cachedResult      *RefreshResult[T]
	ongoingRefresh    *inflightCall[T] // 非 nil 表示当前正有一次 refresh 在跑
	generation        uint64           // 代次计数器，Invalidate 时递增，使 in-flight 异步刷新失效
	refreshFunc       func() (*RefreshResult[T], error)
	staleBehavior     enums.StaleValueBehavior
	prefetchThreshold time.Duration
	clock             Clock
}

// inflightCall 用于 singleflight：所有等待者通过 done channel 收到同一份结果。
type inflightCall[T any] struct {
	done   chan struct{}
	result *RefreshResult[T]
	err    error
}

// NewCachedResultSupplier 创建 CachedResultSupplier
func NewCachedResultSupplier[T any](
	refreshFunc func() (*RefreshResult[T], error),
	staleBehavior enums.StaleValueBehavior,
	prefetchThreshold time.Duration,
) *CachedResultSupplier[T] {
	return &CachedResultSupplier[T]{
		refreshFunc:       refreshFunc,
		staleBehavior:     staleBehavior,
		prefetchThreshold: prefetchThreshold,
		clock:             &SystemClock{},
	}
}

// Get 获取缓存或刷新的结果 (§7.1)
//
// 关键约定：
//   - 任何对 s.cachedResult / s.ongoingRefresh 的读写都必须持 s.mu
//   - refreshFunc 调用必须在锁外（doRefresh 已保证）
func (s *CachedResultSupplier[T]) Get() (*RefreshResult[T], error) {
	s.mu.Lock()
	cached := s.cachedResult
	s.mu.Unlock()

	// 没有缓存 → 同步刷新（多 goroutine 由 singleflight 合并）
	if cached == nil {
		return s.doRefresh()
	}

	// 已过期
	if cached.IsExpired() {
		switch s.staleBehavior {
		case enums.StaleValueBehaviorBlock:
			return s.doRefresh()
		case enums.StaleValueBehaviorAllow:
			// 返回旧值并触发去重的异步刷新
			s.triggerAsyncRefresh()
			return cached, nil
		case enums.StaleValueBehaviorRefresh:
			// 同步刷新；如果新刷新失败则降级返回旧值
			newResult, err := s.doRefresh()
			if err == nil && newResult != nil {
				return newResult, nil
			}
			return cached, nil
		}
	}

	// 即将过期 → 异步预取（去重）
	if cached.WillSoonExpire(s.prefetchThreshold) {
		s.triggerAsyncRefresh()
	}

	return cached, nil
}

// doRefresh 用 singleflight 模式触发一次刷新：
//   - 如果当前没有 in-flight 任务，本 goroutine 创建一个并实际调用 refreshFunc
//   - 如果已有 in-flight 任务，本 goroutine 在 done channel 上等待结果
//
// refreshFunc 调用始终在锁外执行，避免阻塞其他读者。
func (s *CachedResultSupplier[T]) doRefresh() (*RefreshResult[T], error) {
	s.mu.Lock()
	if call := s.ongoingRefresh; call != nil {
		// 已有别人在刷，等结果即可
		s.mu.Unlock()
		<-call.done
		return call.result, call.err
	}

	// 我来当 leader
	call := &inflightCall[T]{done: make(chan struct{})}
	s.ongoingRefresh = call
	s.mu.Unlock()

	// 锁外执行 IO
	result, err := s.refreshFunc()

	// 回写缓存 + 清 in-flight + 在锁内写入 call 结果（保证对等待者的内存可见性）。
	// 约定：所有共享状态变更都在锁内完成，channel 仅用于通知，避免后续重构误把
	// close(done) 提前到赋值之前而引入数据竞争。
	s.mu.Lock()
	if err == nil && result != nil {
		s.cachedResult = result
	}
	s.ongoingRefresh = nil
	call.result = result
	call.err = err
	s.mu.Unlock()

	close(call.done)

	return result, err
}

// triggerAsyncRefresh 启动一次异步刷新；如果已有 in-flight 任务则直接跳过。
// 与 doRefresh 共用同一个 ongoingRefresh 槽位，保证全局至多一个刷新在跑。
func (s *CachedResultSupplier[T]) triggerAsyncRefresh() {
	s.mu.Lock()
	if s.ongoingRefresh != nil {
		s.mu.Unlock()
		return
	}
	call := &inflightCall[T]{done: make(chan struct{})}
	s.ongoingRefresh = call
	currentGen := s.generation
	s.mu.Unlock()

	go func() {
		result, err := s.refreshFunc()

		s.mu.Lock()
		// 仅当 generation 未变化时才回写，防止覆盖 Invalidate() 后的状态
		if err == nil && result != nil && s.generation == currentGen {
			s.cachedResult = result
		}
		s.ongoingRefresh = nil
		s.mu.Unlock()

		call.result = result
		call.err = err
		close(call.done)
	}()
}

// Invalidate 使缓存失效（不会取消正在进行的刷新，但其结果不会回写到已失效后的状态）。
func (s *CachedResultSupplier[T]) Invalidate() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cachedResult = nil
	s.generation++ // 使所有 in-flight 异步刷新失效
}
