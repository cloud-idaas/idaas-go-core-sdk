package strategy

import (
	"context"
	"sync"

	"github.com/cloud-idaas/idaas-go-core-sdk/logger"
)

// NonBlockingPrefetchStrategy 非阻塞预取策略。
//
// 异步执行 refresh，容量 1 的信号量限流（保留防 goroutine 堆积设计）。
type NonBlockingPrefetchStrategy struct {
	refreshSlot chan struct{} // 容量 1，限流信号
	wg          sync.WaitGroup
	closeOnce   sync.Once
	done        chan struct{}
	// mu 串行化 Prefetch 入口("done 检查 + wg.Add")与 Close 的 close(done),
	// 确保 Close 的 wg.Wait 启动后不会再有新的 wg.Add(否则该 goroutine 逃出 Wait 跟踪 → 泄漏)。
	mu sync.Mutex
}

// NewNonBlockingPrefetchStrategy 创建非阻塞预取策略。
func NewNonBlockingPrefetchStrategy() *NonBlockingPrefetchStrategy {
	return &NonBlockingPrefetchStrategy{
		refreshSlot: make(chan struct{}, 1),
		done:        make(chan struct{}),
	}
}

// Prefetch 异步执行 refresh（对齐新接口）。
//
// 先检查 done(Close 后不再接受新 prefetch 请求),激活此前死代码的 done 通道。
// mu 串行化"done 检查 + wg.Add"与 Close 的 close(done),杜绝 wg.Add 发生在
// Close 的 wg.Wait 之后(否则该 goroutine 逃出 Wait 跟踪 → 泄漏)。
func (s *NonBlockingPrefetchStrategy) Prefetch(refresh func()) {
	s.mu.Lock()
	select {
	case <-s.done:
		// 已 Close:不再启动新的后台刷新 goroutine。
		s.mu.Unlock()
		return
	default:
	}
	select {
	case s.refreshSlot <- struct{}{}:
		s.wg.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.wg.Done()
			defer func() { <-s.refreshSlot }()
			defer func() {
				if r := recover(); r != nil {
					logger.Default().Error(context.Background(),
						"prefetch panic recovered",
						"event", "cache.prefetch",
						"status", "panic",
						"error", r)
				}
			}()
			refresh()
		}()
	default:
		s.mu.Unlock()
		// 已有刷新任务在跑，跳过
	}
}

// Close 释放资源（幂等）。
//
// 锁内 close(done) 后释放锁,再 wg.Wait 等待已登记的 goroutine。
// 由于 Prefetch 的 done 检查与 wg.Add 都在 mu 下,Close 拿到 mu 即可确定
// 此后不会再有新的 wg.Add,故 Wait 不会漏等。
func (s *NonBlockingPrefetchStrategy) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		close(s.done)
		s.mu.Unlock()
		s.wg.Wait()
	})
	return nil
}
