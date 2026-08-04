package strategy

import (
	"log/slog"
	"sync"
	"time"

	"github.com/cloud-idaas/idaas-go-core-sdk/cache"
)

// NonBlockingPrefetchStrategy 非阻塞预取策略 (§7.5.2)
//
// 设计要点：
//  1. Start/Stop 通过 sync.Once 保证多次调用幂等，避免 close 已关闭 channel 引发 panic。
//  2. 每次 ticker 触发后异步调用 supplier.Get；当 token endpoint 响应慢/故障时，
//     用容量为 1 的 refreshSlot 信号通道做"并发限流"——已有刷新任务在跑就丢弃本次 tick，
//     避免 goroutine 无界堆积、同把锁被多次竞争抢占。
type NonBlockingPrefetchStrategy[T any] struct {
	supplier    *cache.CachedResultSupplier[T]
	ticker      *time.Ticker
	done        chan struct{}
	wg          sync.WaitGroup
	startOnce   sync.Once
	stopOnce    sync.Once
	refreshSlot chan struct{} // 容量 1，作为"同一时刻最多一个刷新 goroutine"的限流信号
}

// NewNonBlockingPrefetchStrategy 创建非阻塞预取策略
func NewNonBlockingPrefetchStrategy[T any](
	supplier *cache.CachedResultSupplier[T],
	interval time.Duration,
) *NonBlockingPrefetchStrategy[T] {
	return &NonBlockingPrefetchStrategy[T]{
		supplier:    supplier,
		ticker:      time.NewTicker(interval),
		done:        make(chan struct{}),
		refreshSlot: make(chan struct{}, 1),
	}
}

// Start 启动预取（幂等，多次调用只生效一次）
func (s *NonBlockingPrefetchStrategy[T]) Start() {
	s.startOnce.Do(func() {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			for {
				select {
				case <-s.ticker.C:
					// 非阻塞抢占 refreshSlot：抢到才异步刷新，抢不到说明上一次刷新还没完成，
					// 直接丢弃本次 tick 防止 goroutine 堆积。
					select {
					case s.refreshSlot <- struct{}{}:
						s.wg.Add(1)
						go func() {
							defer s.wg.Done()
							defer func() { <-s.refreshSlot }()
							// 预取属"尽力而为"：失败不向调用方传播，但需记录日志以便观测
							// token endpoint 持续故障，避免静默失效。
							if _, err := s.supplier.Get(); err != nil {
								slog.Warn("non-blocking prefetch refresh failed", "error", err.Error())
							}
						}()
					default:
						// 已有刷新任务在跑，跳过本 tick
					}
				case <-s.done:
					return
				}
			}
		}()
	})
}

// Stop 停止预取（幂等，多次调用安全）
func (s *NonBlockingPrefetchStrategy[T]) Stop() {
	s.stopOnce.Do(func() {
		close(s.done)
		s.ticker.Stop()
		s.wg.Wait()
	})
}

// Close 关闭资源（等价于 Stop）
func (s *NonBlockingPrefetchStrategy[T]) Close() {
	s.Stop()
}
