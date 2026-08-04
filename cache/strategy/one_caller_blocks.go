package strategy

import (
	"sync"
	"time"

	"github.com/cloud-idaas/idaas-go-core-sdk/cache"
)

// OneCallerBlocksPrefetchStrategy 单调用者阻塞预取策略 (§7.5.1)
//
// 通过 sync.Once 保证 Stop()/Close() 多次调用幂等，
// 避免 close(已关闭 channel) 引发的 panic。
type OneCallerBlocksPrefetchStrategy[T any] struct {
	supplier  *cache.CachedResultSupplier[T]
	ticker    *time.Ticker
	done      chan struct{}
	wg        sync.WaitGroup
	startOnce sync.Once
	stopOnce  sync.Once
}

// NewOneCallerBlocksPrefetchStrategy 创建单调用者阻塞预取策略
func NewOneCallerBlocksPrefetchStrategy[T any](
	supplier *cache.CachedResultSupplier[T],
	interval time.Duration,
) *OneCallerBlocksPrefetchStrategy[T] {
	return &OneCallerBlocksPrefetchStrategy[T]{
		supplier: supplier,
		ticker:   time.NewTicker(interval),
		done:     make(chan struct{}),
	}
}

// Start 启动预取（幂等，多次调用只生效一次）
func (s *OneCallerBlocksPrefetchStrategy[T]) Start() {
	s.startOnce.Do(func() {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			for {
				select {
				case <-s.ticker.C:
					// 阻塞式触发刷新；调用方可通过 staleBehavior 控制行为。
					// supplier.Get 内部错误已被吞掉（预取场景下不抛出，等下次再试）
					_, _ = s.supplier.Get()
				case <-s.done:
					return
				}
			}
		}()
	})
}

// Stop 停止预取（幂等，多次调用安全）
func (s *OneCallerBlocksPrefetchStrategy[T]) Stop() {
	s.stopOnce.Do(func() {
		close(s.done)
		s.ticker.Stop()
		s.wg.Wait()
	})
}

// Close 关闭资源（等价于 Stop）
func (s *OneCallerBlocksPrefetchStrategy[T]) Close() {
	s.Stop()
}
