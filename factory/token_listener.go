package factory

import (
	"context"
	"time"

	"github.com/cloud-idaas/idaas-go-core-sdk/cache"
	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
	"github.com/cloud-idaas/idaas-go-core-sdk/logger"
)

// listenerEventBufferSize 是 listener 事件队列的容量上限。
// 队列满时丢弃新事件并告警,防止 listener 回调阻塞时 goroutine 无限堆积。
const listenerEventBufferSize = 128

// eventTask 封装一次 listener 派发任务。
type eventTask struct {
	fn    func(TokenListener)
	label string
}

// Experimental: beta 阶段仅定义接口,GA 前签名与回调契约可能变化。
//
// TokenListener 监听凭证缓存的生命周期事件。
// GA 阶段的扩展点,beta 阶段仅定义接口。供宿主应用实现指标上报、
// 审计日志、告警等旁路逻辑,SDK 不在主链路同步执行这些回调。
//
// 调用约定(由 factory 保证):
// - 所有回调**异步**触发,不在持有缓存锁的临界区内调用;
// - 回调内的 panic 被 recover 并记 WARN 日志,绝不影响凭证主链路;
// - 同一事件的多个 listener 按注册顺序串行调用;
// - 回调参数只携带状态快照,不携带可变引用,避免 listener 修改 SDK 内部状态。
type TokenListener interface {
	// OnTokenRefreshed 凭证刷新成功时触发。
	// expiresAt 为新凭证的过期时间;scope 为当前授权范围(可能为空)。
	OnTokenRefreshed(expiresAt time.Time, scope string)

	// OnTokenRefreshFailed 凭证刷新失败时触发。
	// err 为失败原因(已含 error_code);willRetry 表示 SDK 是否会重试。
	OnTokenRefreshFailed(err error, willRetry bool)

	// OnDegradationEntered 进入降级模式时触发(凭证过期且刷新连续失败,
	// 开始返回陈旧值)。consecutiveFailures 为连续失败次数。
	OnDegradationEntered(consecutiveFailures int)

	// OnDegradationExited 退出降级模式时触发(刷新成功,恢复正常)。
	OnDegradationExited(tokenState enums.TokenState)
}

// AddTokenListener 注册一个 TokenListener。
//
// beta 阶段:仅存储 listener,不触发任何事件(GA 接入)。
// 线程安全;可在 Initialize 之前或之后调用,listener 会在后续刷新周期生效。
// 重复注册同一实例不会去重(调用方自行管理)。
func (f *IDaaSCredentialProviderFactory) AddTokenListener(listener TokenListener) {
	if listener == nil {
		return
	}
	f.listenersMu.Lock()
	f.listeners = append(f.listeners, listener)
	f.listenersMu.Unlock()
}

func (f *IDaaSCredentialProviderFactory) notifyTokenRefreshed(expiresAt time.Time, scope string) {
	f.forEachListener(func(l TokenListener) {
		l.OnTokenRefreshed(expiresAt, scope)
	}, "OnTokenRefreshed")
}

func (f *IDaaSCredentialProviderFactory) notifyTokenRefreshFailed(err error, willRetry bool) {
	f.forEachListener(func(l TokenListener) {
		l.OnTokenRefreshFailed(err, willRetry)
	}, "OnTokenRefreshFailed")
}

func (f *IDaaSCredentialProviderFactory) notifyDegradationEntered(consecutiveFailures int) {
	f.forEachListener(func(l TokenListener) {
		l.OnDegradationEntered(consecutiveFailures)
	}, "OnDegradationEntered")
}

func (f *IDaaSCredentialProviderFactory) notifyDegradationExited(state enums.TokenState) {
	f.forEachListener(func(l TokenListener) {
		l.OnDegradationExited(state)
	}, "OnDegradationExited")
}

// startEventWorker 启动单 worker goroutine 消费事件队列。
// 通过 eventOnce 保证全局只启动一次;worker 在进程生命周期内常驻,
// channel 为空时阻塞不消耗 CPU。
func (f *IDaaSCredentialProviderFactory) startEventWorker() {
	f.eventOnce.Do(func() {
		f.eventQueue = make(chan eventTask, listenerEventBufferSize)
		go func() {
			ctx := context.Background()
			for task := range f.eventQueue {
				f.processEventTask(ctx, task)
			}
		}()
	})
}

// processEventTask 处理一个事件任务:拷贝 listener 快照后逐个调用回调。
func (f *IDaaSCredentialProviderFactory) processEventTask(ctx context.Context, task eventTask) {
	f.listenersMu.RLock()
	snapshot := make([]TokenListener, len(f.listeners))
	copy(snapshot, f.listeners)
	f.listenersMu.RUnlock()

	for _, l := range snapshot {
		func() {
			defer func() {
				if r := recover(); r != nil {
					logger.Default().Warn(ctx, "token listener panic recovered",
						"event", task.label,
						"panic", r,
					)
				}
			}()
			task.fn(l)
		}()
	}
}

// forEachListener 拷贝一份 listener 快照后通过有界事件队列派发,
// 确保回调不在持有工厂锁的临界区内执行,且单个 listener 的 panic
// 不影响其他 listener 或 SDK 主链路。
//
// 单 worker + 有界 channel 派发,而非每次调用启动一个 unbounded go func():
// 后者在 listener 回调阻塞 + 刷新持续触发时会让 goroutine 无限堆积。
// channel 满时 drop-and-warn,非阻塞返回,不耗尽宿主资源。
func (f *IDaaSCredentialProviderFactory) forEachListener(fn func(TokenListener), eventLabel string) {
	f.listenersMu.RLock()
	hasListeners := len(f.listeners) > 0
	f.listenersMu.RUnlock()

	if !hasListeners {
		return
	}

	f.startEventWorker()
	select {
	case f.eventQueue <- eventTask{fn: fn, label: eventLabel}:
	default:
		// 队列满:丢弃事件并告警,不阻塞刷新主链路。
		logger.Default().Warn(context.Background(),
			"listener event queue full, dropping event",
			"event", eventLabel)
	}
}

// dispatchRefreshEvent 把 cache 包级 hook 收到的 RefreshEvent 转译成
// TokenListener 的具体回调。
//
// 由 IDaaSCredentialProviderFactory.Initialize 安装到 cache.SetRefreshObserverHook,
// 在 cache.commitRefresh 锁外派发时被调用。RefreshEvent 只携带状态快照,
// 这里按 Kind 路由到对应的 notify* 方法;notify* 内部再异步快照+recover 转发给 listener,
// 因此本方法本身不会阻塞凭证主链路,也不会因 listener panic 击穿。
//
// willRetry 语义:stale 退避窗口内的失败 SDK 会继续返回旧值并按窗口重试,
// 视为 willRetry=true;降级退出视为恢复。事件本身不区分同步/异步刷新路径,
// 因为对 listener 而言"刷新成功/失败"与触发路径无关。
func (f *IDaaSCredentialProviderFactory) dispatchRefreshEvent(ev cache.RefreshEvent) {
	switch ev.Kind {
	case cache.RefreshEventRefreshed:
		// scope 从 RefreshEvent.Scope 获取(由 CachedResultSupplier.WithScope 设置)。
		f.notifyTokenRefreshed(ev.ExpiresAt, ev.Scope)
	case cache.RefreshEventRefreshFailed:
		// stale 退避保证 SDK 会在窗口后重试,标记 willRetry=true。
		f.notifyTokenRefreshFailed(ev.Err, true)
	case cache.RefreshEventDegradationEntered:
		f.notifyDegradationEntered(ev.ConsecutiveFailures)
	case cache.RefreshEventDegradationExited:
		// 降级退出 = 凭证恢复健康。
		f.notifyDegradationExited(enums.TokenStateHealthy)
	default:
		// 未知事件类型:不静默吞掉,记一条 WARN 便于排查 hook 版本不匹配。
		logger.Default().Warn(context.Background(), "unknown refresh event kind ignored",
			"event", "cache.refresh", "kind", string(ev.Kind))
	}
}
