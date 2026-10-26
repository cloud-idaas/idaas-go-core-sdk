package cache

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cloud-idaas/idaas-go-core-sdk/constants"
	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
	"github.com/cloud-idaas/idaas-go-core-sdk/errors"
	"github.com/cloud-idaas/idaas-go-core-sdk/logger"
)

// CachedResultSupplier 缓存结果供应商。关键并发约束：
// refreshFunc 必须锁外执行；singleflight 合并并发刷新；异步预取去重；
// generation counter 防 Invalidate() 后异步刷新覆盖已失效状态（同步/异步回填均校验，
// 提取为共用 commitRefresh）；所有取时点走注入的 Clock 以支持确定性测试。
type CachedResultSupplier[T any] struct {
	mu             sync.RWMutex
	cachedResult   *RefreshResult[T]
	ongoingRefresh *inflightCall[T]
	generation     uint64
	refreshFunc    func(context.Context) (*RefreshResult[T], error)
	staleBehavior  enums.StaleValueBehavior
	clock          Clock
	// baseCtx 是 supplier 级"宿主可关闭"上下文,由 factory Initialize 注入
	// (factory baseCtx,Reset 时取消)。新写 worker(runRefreshAndCommit)的刷新
	// 操作 ctx 由 WithTimeout(baseCtx, asyncTimeout) 派生,使 Reset/Shutdown 能
	// 主动取消在飞 worker("goroutine 可被宿主关闭")。nil 时回退 Background
	// (零回归,仅测试/非 factory 直接构造路径)——生产路径 factory 始终注入非 nil。
	baseCtx             context.Context
	refreshLockWait     time.Duration    // 等待他人刷新的软上限（5s，对齐 Java/Python）：超时后若有未过期的旧值则直接返回
	asyncRefreshTimeout time.Duration    // 后台刷新的整体超时，需覆盖 connect+read 超时上限
	staleRetryBackoff   time.Duration    // stale/过期阶段刷新失败后的退避窗口，窗口内直接返回旧值不再打 IdP
	lastRefreshFailure  time.Time        // 最近一次刷新失败的时刻；成功后清零
	consecutiveFailures int              // 连续刷新失败次数；用于降级事件判定，成功后清零
	prefetchStrategy    PrefetchStrategy // 可选预取策略 (接通 cache/strategy)
	scope               string           // 绑定的 scope，在 RefreshEvent 中携带
}

type RefreshEventKind string

const (
	RefreshEventRefreshed     RefreshEventKind = "refreshed"
	RefreshEventRefreshFailed RefreshEventKind = "refresh_failed"
	// 进入降级（首次连续失败）
	RefreshEventDegradationEntered RefreshEventKind = "degradation_entered"
	// 退出降级（刷新恢复成功）
	RefreshEventDegradationExited RefreshEventKind = "degradation_exited"
)

// RefreshEvent 刷新生命周期事件。
// 由 CachedResultSupplier 在刷新结果提交时产生，通过包级 hook 派发给
// factory 注册的 TokenListener。携带状态快照，不含可变引用。
type RefreshEvent struct {
	Kind                RefreshEventKind
	Err                 error     // 失败原因（成功时为 nil）
	ExpiresAt           time.Time // 新凭证过期时间（成功时有效）
	ConsecutiveFailures int       // 连续失败次数（降级事件有效）
	Scope               string    // 绑定的 scope，由 WithScope 设置
}

// RefreshObserver 由调用方注入的刷新事件回调。
// 通过包级 hook 安装，避免 cache 包反向依赖 factory；nil 时为 no-op。
type RefreshObserver func(ev RefreshEvent)

// refreshObserverHook 包级刷新观察 hook，由 factory 在 Initialize 时安装、Reset 时清除。
// 全局可变状态：通过 observerMu 保护 Set/Get，与 defaultClock 的同步模式一致。
var (
	refreshObserverHook RefreshObserver
	observerMu          sync.RWMutex
)

// SetRefreshObserverHook 安装包级刷新观察 hook。fn 为 nil 表示清除。
func SetRefreshObserverHook(fn RefreshObserver) {
	observerMu.Lock()
	refreshObserverHook = fn
	observerMu.Unlock()
}

// emitRefreshEvent 安全触发刷新观察 hook。nil 或未安装时为 no-op。
// 必须在持有 supplier 锁的临界区之外调用，避免阻塞凭证主链路。
func emitRefreshEvent(ev RefreshEvent) {
	observerMu.RLock()
	fn := refreshObserverHook
	observerMu.RUnlock()
	if fn != nil {
		fn(ev)
	}
}

// emitRefreshEventSafe 在 recover 包裹下派发事件,单个 observer 回调 panic
// 不影响后续事件派发和 call.done 的释放。
func emitRefreshEventSafe(ev RefreshEvent) {
	defer func() { _ = recover() }()
	emitRefreshEvent(ev)
}

// inflightCall 用于 singleflight。
//
// done 由 closeDone 幂等关闭(sync.Once 守卫),避免双关 panic。
// result/err 在 commitRefresh 持锁写入,waiter 在 done 关闭后无锁读取。
type inflightCall[T any] struct {
	done   chan struct{}
	once   sync.Once
	result *RefreshResult[T]
	err    error
}

// closeDone 幂等关闭 done channel。
// 由 commitRefresh(正常完成)与 runRefreshAndCommit recover(panic)各调用一次,
// sync.Once 保证仅第一次真正 close,后续为 no-op,消除双关 panic。
func (c *inflightCall[T]) closeDone() {
	c.once.Do(func() {
		close(c.done)
	})
}

// defaultRefreshLockWait 刷新锁等待上限 (对齐 Java/Python 5s)。
const defaultRefreshLockWait = 5 * time.Second

// defaultAsyncRefreshTimeout 后台刷新整体超时。HTTP 层 connect/read 超时各自上限 60s，
// 这里取二者之和，避免合法的慢请求被提前截断；同时兜住不受 HTTP 超时约束的调用（如元数据服务）。
const defaultAsyncRefreshTimeout = 2 * time.Minute

// defaultStaleRetryBackoff stale/过期阶段刷新失败后的退避窗口。
// IdP 故障期间每个窗口最多同步打一次 IdP，其余请求直接拿旧值，避免放大故障。
const defaultStaleRetryBackoff = 10 * time.Second

// PrefetchStrategy 预取策略接口 (接通 cache/strategy)。
//
// 与 cache/strategy.PrefetchStrategy 签名一致（结构化类型自动满足），
// 调用方可注入 cache/strategy.NonBlockingPrefetchStrategy 等实现，
// 也可自定义。为 nil 时回退到内置异步刷新（triggerAsyncRefresh）。
type PrefetchStrategy interface {
	Prefetch(refresh func())
	Close() error
}

// NewCachedResultSupplier 创建 CachedResultSupplier。
//
// 注:旧版第三参 prefetchThreshold 已删除——该字段在构造后被设但全程
// 不被读(预取时间点由 RefreshResult 内置三时点 PrefetchTime 驱动),属死代码。
// 构造器签名变更属 v0.x 允许的 breaking,CHANGELOG 登记。
func NewCachedResultSupplier[T any](
	refreshFunc func(context.Context) (*RefreshResult[T], error),
	staleBehavior enums.StaleValueBehavior,
) *CachedResultSupplier[T] {
	return &CachedResultSupplier[T]{
		refreshFunc:         refreshFunc,
		staleBehavior:       staleBehavior,
		clock:               nil, // nil → now() 回退到 GetClock()，与 RefreshResult 使用同一时钟源
		refreshLockWait:     defaultRefreshLockWait,
		asyncRefreshTimeout: defaultAsyncRefreshTimeout,
		staleRetryBackoff:   defaultStaleRetryBackoff,
	}
}

// WithClock 注入 Clock (接通)。
func (s *CachedResultSupplier[T]) WithClock(c Clock) *CachedResultSupplier[T] {
	if c != nil {
		// 写 s.clock 必须与 now()/读侧同步,避免运行期重配时钟时的 data race。
		// 与 WithPrefetchStrategy 保持一致契约("即便该方法是构造期调用,也通过锁
		// 与读侧保持一致契约"),与包级 SetClock 的 observerMu 同步模式对齐。
		s.mu.Lock()
		s.clock = c
		s.mu.Unlock()
	}
	return s
}

// now 返回当前时间。优先使用注入的 per-supplier 时钟 (WithClock)，
// 否则回退到包级时钟 GetClock()，与 NewRefreshResult 使用同一时钟源 (修复)。
//
// 读侧持 RLock 与 WithClock 的写 (mu.Lock) 同步，消除运行期重配时钟时的 data race。
// nowLocked 供已持有 s.mu.Lock 的写路径调用 (如 commitRefresh 失败分支写 lastRefreshFailure)，
// 复用外层写锁即可，自取 RLock 会与已持写锁死锁。
func (s *CachedResultSupplier[T]) now() time.Time {
	s.mu.RLock()
	c := s.clock
	s.mu.RUnlock()
	if c != nil {
		return c.Now()
	}
	return GetClock().Now()
}

// nowLocked 是 now 的"调用方已持锁"版本：不取 RLock，依赖外层已持有的 s.mu.Lock
// 排除并发 WithClock 写。仅在 commitRefresh 持写锁的分支内调用。
func (s *CachedResultSupplier[T]) nowLocked() time.Time {
	if s.clock != nil {
		return s.clock.Now()
	}
	return GetClock().Now()
}

// WithPrefetchStrategy 注入预取策略 (接通 cache/strategy)。
//
// 注入后，stale/预取阶段的异步刷新委托给策略执行（策略自行决定同步或异步、
// 是否限流）。为 nil 时回退到内置 triggerAsyncRefresh（容量 1 的 goroutine 限流）。
func (s *CachedResultSupplier[T]) WithPrefetchStrategy(ps PrefetchStrategy) *CachedResultSupplier[T] {
	if ps != nil {
		// 写 prefetchStrategy 必须与 Close/triggerAsyncRefresh 的读写同步,
		// 避免并发注入与关闭时的 data race。即便该方法是构造期调用,
		// 也通过锁与读侧保持一致契约。
		s.mu.Lock()
		s.prefetchStrategy = ps
		s.mu.Unlock()
	}
	return s
}

// WithScope 设置 supplier 绑定的 scope。
// 该 scope 会携带在 RefreshEvent 中，由 factory 转发给 TokenListener，
// 使 listener 能区分不同 scope 的刷新事件。
// 应在 supplier 创建后、首次刷新前调用。
func (s *CachedResultSupplier[T]) WithScope(scope string) *CachedResultSupplier[T] {
	s.mu.Lock()
	s.scope = scope
	s.mu.Unlock()
	return s
}

// WithAsyncRefreshTimeout 覆盖 detached 刷新上下文的超时上限。
// 默认 defaultAsyncRefreshTimeout=2min 适用于机器凭据(HTTP connect+read 上限 60s);
// HUMAN device flow 需最长 180s(MaxWaitIntervalSeconds)等待用户扫码,默认 120s 会截断合法流程,须调大以覆盖完整等待窗口。
// 应在 supplier 创建后、首次刷新前调用。
func (s *CachedResultSupplier[T]) WithAsyncRefreshTimeout(d time.Duration) *CachedResultSupplier[T] {
	if d > 0 {
		s.mu.Lock()
		s.asyncRefreshTimeout = d
		s.mu.Unlock()
	}
	return s
}

// WithBaseContext 注入 supplier 级"宿主可关闭"基础上下文。
//
// 由 factory Initialize 注入(factory baseCtx,Reset 时取消)。新写 worker
// runRefreshAndCommit 的刷新操作 ctx = WithTimeout(baseCtx, asyncTimeout),
// 使 Reset/Shutdown 主动取消在飞 worker("goroutine 可被宿主关闭")。
// nil 时回退 Background(零回归,仅测试/非 factory 直接构造路径)。生产路径
// factory 始终注入非 nil baseCtx,无须调用方额外 opt-in。应在首次刷新前调用。
//
// Experimental:beta 阶段接入;GA 前若 baseCtx 语义统一化会调整注入点。
func (s *CachedResultSupplier[T]) WithBaseContext(ctx context.Context) *CachedResultSupplier[T] {
	s.mu.Lock()
	s.baseCtx = ctx
	s.mu.Unlock()
	return s
}

// 注入的 PrefetchStrategy(如 NonBlockingPrefetchStrategy / OneCallerBlocksPrefetchStrategy)
// 可能持有 goroutine / ticker,不 Close 会在 supplier 被丢弃后泄漏。
// 未注入策略(内置异步刷新,走一次性 goroutine + channel)时 Close 为 no-op。
//
// 多次调用安全:首次调用清空 prefetchStrategy 引用并 Close;后续调用直接返回。
// 调用时机:supplier 不再被使用时(如 provider 重建、factory Reset、进程优雅退出)。
func (s *CachedResultSupplier[T]) Close() error {
	s.mu.Lock()
	ps := s.prefetchStrategy
	s.prefetchStrategy = nil
	s.mu.Unlock()
	if ps != nil {
		return ps.Close()
	}
	return nil
}

// Get 获取缓存或刷新的结果。
// 内部委托给 GetWithContext,使用 context.Background()。
func (s *CachedResultSupplier[T]) Get() (*RefreshResult[T], error) {
	return s.GetWithContext(context.Background())
}

// GetWithContext 获取缓存或刷新的结果,带 context。
//
// ctx 仅透传到**同步刷新**路径(cache miss / 已过期的 Block / Refresh)。
// **异步预取**路径使用 context.Background():预取发生在后台 goroutine,
// 不应绑定到某个已经返回的请求的 ctx,否则请求结束后预取会被立即取消。
func (s *CachedResultSupplier[T]) GetWithContext(ctx context.Context) (*RefreshResult[T], error) {
	// 读路径只读 s.cachedResult，不写，用 RLock 避免热路径读串行化。
	s.mu.RLock()
	cached := s.cachedResult
	s.mu.RUnlock()

	// 没有缓存 → 同步刷新
	if cached == nil {
		return s.doRefresh(ctx)
	}

	now := s.now()

	// 已过期
	if now.After(cached.ExpiresAt) {
		switch s.staleBehavior {
		case enums.StaleValueBehaviorBlock:
			// 退避窗口内不重试,防 IdP 雪崩;BLOCK 硬保证"不返回过期值"
			// 仍成立(返回 ErrRefreshInBackoff 而非旧值)。窗口外才同步刷新。
			// commitRefresh 不区分 staleBehavior 设 lastRefreshFailure,
			// 故 BLOCK 首次 doRefresh 失败即进退避,后续 BLOCK 调用立即命中本分支。
			if s.inStaleBackoff(now) {
				return nil, ErrRefreshInBackoff
			}
			return s.doRefresh(ctx)
		case enums.StaleValueBehaviorAllow:
			// 已过期的值返回时带错误信号，不是 nil
			// 退避窗口内不重试后台刷新，避免对故障 IdP 逐请求放大。
			if !s.inStaleBackoff(now) {
				s.triggerAsyncRefresh()
			}
			return cached, ErrStaleCredentialReturned
		case enums.StaleValueBehaviorRefresh:
			if s.inStaleBackoff(now) {
				return cached, ErrStaleCredentialReturned
			}
			newResult, err := s.doRefresh(ctx)
			if err == nil && newResult != nil {
				return newResult, nil
			}
			// 刷新失败：返回旧值，带错误信号
			logStaleFallback(err, "expired")
			return cached, ErrStaleCredentialReturned
		default:
			// 未知 staleValueBehavior 不应 fall-through 后把过期凭证当成功返回。
			return nil, ErrInvalidStaleValueBehavior
		}
	}

	// 进入 stale 阶段（StaleTime < now < ExpiresAt）
	if now.After(cached.StaleTime) {
		switch s.staleBehavior {
		case enums.StaleValueBehaviorBlock:
			// stale 窗口内 Block 不触发同步刷新，break 落入下方预取检查
			// （与原 fall-through 行为一致：Block 仍可触发后台预取）。
			break
		case enums.StaleValueBehaviorAllow:
			// stale 但未过期：返回旧值不带错误，触发异步刷新
			// 退避窗口内不重试后台刷新。
			if !s.inStaleBackoff(now) {
				s.triggerAsyncRefresh()
			}
			return cached, nil
		case enums.StaleValueBehaviorRefresh:
			// 上次刷新失败后的退避窗口内直接返回旧值，不再逐请求同步打 IdP。
			if s.inStaleBackoff(now) {
				return cached, nil
			}
			newResult, err := s.doRefresh(ctx)
			if err == nil && newResult != nil {
				return newResult, nil
			}
			logStaleFallback(err, "stale")
			return cached, nil
		default:
			// 未知 staleValueBehavior 返回配置错误，不 fall-through 成功。
			return nil, ErrInvalidStaleValueBehavior
		}
	}

	// 到达预取时间点 → 异步预取
	if now.After(cached.PrefetchTime) {
		// 退避窗口内不重试后台预取刷新。
		if !s.inStaleBackoff(now) {
			s.triggerAsyncRefresh()
		}
	}

	return cached, nil
}

// inStaleBackoff 判断是否仍处于上次刷新失败后的退避窗口内。
func (s *CachedResultSupplier[T]) inStaleBackoff(now time.Time) bool {
	s.mu.RLock()
	last := s.lastRefreshFailure
	s.mu.RUnlock()
	return !last.IsZero() && now.Sub(last) < s.staleRetryBackoff
}

// logStaleFallback 同步刷新失败、降级返回旧值时记录一次 WARN。
// 错误本身没有返回给调用方，不记日志就成了盲区；退避窗口保证每窗口最多一条。
func logStaleFallback(err error, phase string) {
	msg := "refresh returned no result"
	if err != nil {
		msg = err.Error()
	}
	logger.Default().Warn(context.Background(), "credential refresh failed, returning cached value",
		"event", "cache.refresh", "status", "fallback", "phase", phase, "error", msg)
}

// doRefresh 用 singleflight 模式触发一次刷新(leader/waiter 分离)。
//
// leader(无 ongoingRefresh):登记 call → `go runRefreshAndCommit(...)` →
// `select { case <-call.done; case <-ctx.Done() }`(plain select,不走 waitInflight)。
// leader 在 cache-miss / BLOCK expired 场景无旧值可 fallback,waitInflight 的 5s
// 旧值 fallback 在 leader 路径不应触发(否则可能误返 nil);leader 与 waiter 路径
// 分离是有意对称。leader ctx.Done() 返回包装后的 ClientRequestCanceled
// (底层 ctx.Err() 经 %w 透传,调用方可 errors.Is 区分取消原因)。
// waiter(ongoingRefresh != nil):走 waitInflight(含 5s 旧值 fallback,对
// stale+Refresh 有旧值场景生效;cache-miss/expired 无旧值不触发 fallback 分支)。
//
// leader 的刷新 worker 在独立 goroutine 中执行(detached from 调用方 ctx),
// refresh 操作 ctx = WithTimeout(baseCtx, asyncTimeout):单个调用方 ctx 取消
// 不取消所有 waiter 共享的刷新,但 baseCtx(宿主级) 可取消在飞 worker。
func (s *CachedResultSupplier[T]) doRefresh(ctx context.Context) (*RefreshResult[T], error) {
	if ctx == nil {
		ctx = context.Background()
	}
	s.mu.Lock()
	if call := s.ongoingRefresh; call != nil {
		s.mu.Unlock()
		return s.waitInflight(ctx, call)
	}

	call := &inflightCall[T]{done: make(chan struct{})}
	s.ongoingRefresh = call
	myGeneration := s.generation
	// 在锁内快照 asyncTimeout 与 baseCtx,避免释放锁后 goroutine 读取与
	// WithAsyncRefreshTimeout/WithBaseContext 的写产生 data race。
	asyncTimeout := s.asyncRefreshTimeout
	baseCtx := s.baseCtx
	s.mu.Unlock()

	// leader 入口短路:调用方 ctx 已取消则不发起刷新(不消耗 IdP 配额、不登记 in-flight)。
	if err := ctx.Err(); err != nil {
		// 须清掉刚登记的 in-flight 槽,否则后续请求都走 waiter 路径死等一个永不完成的 call。
		cancelErr := errors.NewCacheError(
			constants.ClientRequestCanceled,
			"credential request canceled by caller",
			err, // ctx.Err() 经 CacheError.Unwrap 透传
		)
		// 持锁清槽并写 call.err,与 commitRefresh 同款:
		// unlock(423) 与此处 ctx 检查之间的窗口内,若有并发 waiter 进入 waitInflight,
		// 须保证 waiter 经 <-call.done 读到 (nil, cancelErr) 而非 (nil,nil)——
		// 否则 abstract_refreshed_provider.go:70 的 result.Value 将 nil deref,
		// panic 经同步调用栈逃逸宿主(worker 的顶层 recover 不覆盖此路径)。
		s.clearOngoingIfMatch(call, cancelErr)
		call.closeDone()
		return nil, cancelErr
	}

	// leader 启动 worker;worker 用 detached refresh ctx(baseCtx 派生),不被调用方 ctx 取消。
	go func() {
		// worker 的错误已经通过 call 提交给 waiter 并在内部落日志;
		// goroutine 语境下返回值没有可行动的消费方,显式丢弃并留注释(errcheck)。
		_ = s.runRefreshAndCommit(asyncTimeout, myGeneration, call, baseCtx)
	}()

	// leader plain select:要么刷新完成,要么调用方 ctx 取消(此时 worker 仍在后台跑,
	// 其结果由 commitRefresh 提交给后续的 waiter)。:不走 waitInflight 的 5s fallback。
	select {
	case <-call.done:
		return call.result, call.err
	case <-ctx.Done():
		return nil, errors.NewCacheError(
			constants.ClientRequestCanceled,
			"credential request canceled by caller",
			ctx.Err(),
		)
	}
}

// clearOngoingIfMatch 在 ongoingRefresh==call 时清槽(对齐 commitRefresh 的
// "只清自己 in-flight 槽"逻辑,避免误清新 call 的槽位),并持锁写入 call.err。
//
// leader-abandon 路径(调用方 ctx 已取消,见 doRefresh) 调用本方法:
// unlock(doRefresh) 与 ctx 检查之间的窗口内,若有并发 waiter 进入
// waitInflight,须保证 waiter 经 <-call.done 读到 (nil, cancelErr) 而非 (nil,nil),
// 否则 abstract_refreshed_provider.go:70 的 result.Value 将 nil deref,
// panic 经同步调用栈逃逸宿主(worker 的顶层 recover 不覆盖此路径)。
// 与 commitRefresh 持锁写 call.err 同款。
func (s *CachedResultSupplier[T]) clearOngoingIfMatch(call *inflightCall[T], cancelErr error) {
	s.mu.Lock()
	if s.ongoingRefresh == call {
		s.ongoingRefresh = nil
	}
	call.err = cancelErr
	s.mu.Unlock()
}

// runRefreshAndCommit 是 leader 同步刷新与 async 刷新共用的 worker 体。
//
// 顶层 recover:任何 panic(refreshFunc/commitRefresh/err.Error())都写非 nil
// CacheError(RefreshPanicRecovered)经 commitRefresh 提交 + closeDone 由
// commitRefresh 的 defer 兜底,不让 waiter 拿 (nil,nil) 也不让 panic
// 击穿宿主。返回 err 供 async 路径日志(:异步失败
// 日志仅 async 路径记,worker 自身不重复记)。
// 刷新操作 ctx = WithTimeout(baseCtx, asyncTimeout):可被 baseCtx(宿主)取消,
// 不绑定任一调用方 ctx(worker 是共享刷新)。baseCtx nil → Background(零回归)。
func (s *CachedResultSupplier[T]) runRefreshAndCommit(
	asyncTimeout time.Duration,
	myGeneration uint64,
	call *inflightCall[T],
	baseCtx context.Context,
) (retErr error) {
	// 顶层 recover:兜住 safeRefresh 之外的 commitRefresh / err.Error() 等路径。
	defer func() {
		if r := recover(); r != nil {
			// 写非 nil CacheError,recovered 转 string 入 message(不入 kv),cause=nil。
			recErr := errors.NewCacheError(
				constants.RefreshPanicRecovered,
				fmt.Sprintf("refresh panicked; recovered: %v", r),
				nil,
			)
			// recover 路径也走 commitRefresh,统一 generation 校验 + lastRefreshFailure 设置 +
			// 事件派发 + closeDone,保证 waiter 拿到一致结果而非 (nil,nil)。
			// commitRefresh 自身已 panic-safe(scoped anon func),此处 inner recover
			// 仅防极小概率的二次 panic 击穿顶层。
			func() {
				defer func() { _ = recover() }()
				s.commitRefresh(nil, recErr, myGeneration, call)
			}()
			retErr = recErr
			// 日志 ctx 用 WithoutCancel(baseCtx):refresh ctx 可能已被取消,日志仍须落盘
			// 不得用 context.Background() 也不得用会被取消的 refresh ctx。
			logCtx := logger.WithoutCancel(s.effectiveBaseContext(baseCtx))
			logger.Default().Error(logCtx,
				"refresh worker panic recovered",
				"event", "cache.refresh", "status", "panic", "error", fmt.Sprint(r))
		}
		// 终极兜底 closeDone:正常路径下 commitRefresh 已在末尾 close 过,
		// 此处 sync.Once no-op;panic 路径下若恢复分支的 commitRefresh 二次 panic 被
		// inner recover 吞掉(极小概率),此处保证 done 仍被 close,waiter/leader 绝不死等。
		// 此时 call.err 可能仍为零值,但 done 被 close 让 waiter 不阻塞,由其重试兜底。
		call.closeDone()
	}()

	if baseCtx == nil {
		baseCtx = context.Background() // 零回归:非 factory 直接构造(测试)路径
	}
	refreshCtx, cancel := context.WithTimeout(baseCtx, asyncTimeout)
	defer cancel()
	result, err := s.safeRefresh(refreshCtx)
	s.commitRefresh(result, err, myGeneration, call)
	// 返回 commitRefresh 覆盖后的 call.err(generation 不匹配时被覆盖为
	// ErrRefreshInvalidated);供 async 路径日志。sync(leader)路径用 call.result/
	// call.err 自己读,不走这里返回值。
	return call.err
}

// effectiveBaseContext 在锁内快照 baseCtx 给日志 ctx 用(recover 路径)。
// runRefreshAndCommit 的 baseCtx 入参可能为 nil(已 fallback Background),
// 但日志 WithoutCancel 希望拿到原始 baseCtx(若有)以便透传 trace 关联。
// 此处统一:入参非 nil 用入参,否则锁内再读一次字段(可能被 WithBaseContext 后注入)。
func (s *CachedResultSupplier[T]) effectiveBaseContext(baseCtx context.Context) context.Context {
	if baseCtx != nil {
		return baseCtx
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.baseCtx
}

// waitInflight 等待进行中的刷新完成，同时响应 ctx 与 refreshLockWait。
func (s *CachedResultSupplier[T]) waitInflight(ctx context.Context, call *inflightCall[T]) (*RefreshResult[T], error) {
	timer := time.NewTimer(s.refreshLockWait)
	defer timer.Stop()
	select {
	case <-call.done:
		return call.result, call.err
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		s.mu.RLock()
		cached := s.cachedResult
		s.mu.RUnlock()
		if cached != nil && !s.now().After(cached.ExpiresAt) {
			return cached, nil
		}
	}
	// 没有可用旧值，只能继续等刷新结果或 ctx 取消
	select {
	case <-call.done:
		return call.result, call.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// safeRefresh 执行 refreshFunc，并把 panic 转成 CacheError。
//
// 若 refreshFunc 返回 (nil result, nil err)，调用方解引用 result.Value 会 panic;
// 在此归一化为 (nil, ErrNilRefreshResult)，确保 leader 与所有 waiter 收到非 nil 错误。
func (s *CachedResultSupplier[T]) safeRefresh(ctx context.Context) (result *RefreshResult[T], err error) {
	defer func() {
		if r := recover(); r != nil {
			result = nil
			err = errors.NewCacheError(
				constants.UnexpectedError,
				fmt.Sprintf("refresh panic: %v", r),
				nil,
			)
			logger.Default().Error(context.Background(), "refresh panic recovered",
				"event", "cache.refresh", "status", "panic", "error", fmt.Sprint(r))
		}
	}()
	result, err = s.refreshFunc(ctx)
	// (nil result, nil err) → panic on result.Value dereference;
	// 归一化为非 nil 错误,使 commitRefresh/waiters/callers 均看到失败。
	if result == nil && err == nil {
		err = ErrNilRefreshResult
	}
	return result, err
}

// triggerAsyncRefresh 启动一次异步刷新。
// 使用 context.Background():预取是后台行为,不应绑定到调用方请求的 ctx。
//
// 如果注入了 PrefetchStrategy，委托给策略执行；
// 否则回退到内置 goroutine 限流刷新。
func (s *CachedResultSupplier[T]) triggerAsyncRefresh() {
	// 读 prefetchStrategy 必须与 Close 的写同步,避免 data race。
	// 取快照后在锁外调用 Prefetch,不持锁执行外部代码(策略可能 wg.Wait 阻塞,
	// 持锁等待会与读路径 RLock 互斥,拖慢热路径)。
	s.mu.RLock()
	ps := s.prefetchStrategy
	s.mu.RUnlock()
	if ps != nil {
		ps.Prefetch(func() {
			s.doAsyncRefresh()
		})
		return
	}

	// 内置异步刷新（无策略注入时的默认行为）
	s.doAsyncRefresh()
}

// doAsyncRefresh 执行实际的异步刷新逻辑（singleflight + generation 校验）。
//
// 复用 runRefreshAndCommit worker:不再独立 WithTimeout(Background),
// 改传 baseCtx,使 async worker 也可被宿主(baseCtx) 取消。
// 异步失败日志仅在此(async 路径)记一次,worker 自身不重复记;日志 ctx 用
// logger.WithoutCancel(baseCtx)——refresh ctx 取消后日志仍须落盘。
func (s *CachedResultSupplier[T]) doAsyncRefresh() {
	s.mu.Lock()
	if s.ongoingRefresh != nil {
		s.mu.Unlock()
		return
	}
	call := &inflightCall[T]{done: make(chan struct{})}
	s.ongoingRefresh = call
	myGeneration := s.generation
	// 在锁内快照 asyncRefreshTimeout 与 baseCtx,避免 goroutine 读取与
	// WithAsyncRefreshTimeout / WithBaseContext 的写产生 data race。
	asyncTimeout := s.asyncRefreshTimeout
	baseCtx := s.baseCtx
	s.mu.Unlock()

	go func() {
		err := s.runRefreshAndCommit(asyncTimeout, myGeneration, call, baseCtx)
		// 后台刷新的错误没有调用方接收,在此记录一次,消除可观测性盲区。
		// 同步路径的错误已返回给调用方,不在这里重复记录。
		// 刷新失败事件经 commitRefresh → emitRefreshEvent 派发给 TokenListener。
		if err != nil {
			logCtx := logger.WithoutCancel(s.effectiveBaseContext(baseCtx))
			logger.Default().Warn(logCtx,
				"background credential refresh failed",
				"event", "cache.refresh", "status", "failed",
				"error", err.Error())
		}
	}()
}

// commitRefresh 统一回填函数。
//
// generation 校验：若 generation 不匹配（说明期间发生过 Invalidate），丢弃本次结果。
// 修复：lastRefreshFailure 与 consecutiveFailures 也必须受 generation guard 保护，
// 否则旧 generation 的成功会把新 generation 因真实失败而设的退避窗口清零（惊群），
// 或旧 generation 的失败给新 generation 强加一个未预期的退避。
// 事件派发：在锁外异步触发 RefreshEvent，由 factory 转发给 TokenListener。
//
// 锁管理改 scoped anon func:临界区 panic 也释放 mu(supplier 不死锁),
// event 派发仍在锁外(注释契约)。closeDone 用 sync.Once 幂等:
// commitRefresh 正常完成与 worker recover 路径各调用一次,仅首次真正 close。
func (s *CachedResultSupplier[T]) commitRefresh(
	result *RefreshResult[T],
	err error,
	myGeneration uint64,
	call *inflightCall[T],
) {
	var events []RefreshEvent

	// scoped anon func:临界区 panic 也释放 mu。
	func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		// 读取 scope 用于事件携带,在锁内读取避免与 WithScope 写竞态。
		evScope := s.scope
		if s.generation == myGeneration {
			if err == nil && result != nil {
				s.cachedResult = result
				s.lastRefreshFailure = time.Time{}
				wasDegraded := s.consecutiveFailures > 0
				s.consecutiveFailures = 0
				if wasDegraded {
					events = append(events, RefreshEvent{Kind: RefreshEventDegradationExited, ExpiresAt: result.ExpiresAt, Scope: evScope})
				}
				events = append(events, RefreshEvent{Kind: RefreshEventRefreshed, ExpiresAt: result.ExpiresAt, Scope: evScope})
			} else {
				s.lastRefreshFailure = s.nowLocked()
				wasDegraded := s.consecutiveFailures > 0
				s.consecutiveFailures++
				cf := s.consecutiveFailures
				events = append(events, RefreshEvent{Kind: RefreshEventRefreshFailed, Err: err, ConsecutiveFailures: cf, Scope: evScope})
				if !wasDegraded {
					events = append(events, RefreshEvent{Kind: RefreshEventDegradationEntered, Err: err, ConsecutiveFailures: cf, Scope: evScope})
				}
			}
		} else {
			// generation 不匹配:丢弃结果,告知 waiter 刷新已失效应重试。
			result = nil
			err = ErrRefreshInvalidated
		}
		// 只清掉"自己"的 in-flight 槽,避免旧 call 的 commit 把新 call 占用的槽误清成 nil。
		if s.ongoingRefresh == call {
			s.ongoingRefresh = nil
		}
		call.result = result
		call.err = err
	}()

	// 事件派发仍在锁外(注释契约)。
	for _, ev := range events {
		emitRefreshEventSafe(ev)
	}

	// closeDone 置于函数末尾:确保 call.err 已在 scoped anon 内写定后才 close,
	// leader/waiter 经 <-call.done 同步读到一致的 (result, err),无"done 已 close
	// 但 err 仍为零值"的竞态。panic 路径下此处不触发(panic 在 scoped anon 内抛出,
	// 跳过末尾 defer 注册),改由 runRefreshAndCommit 的顶层 defer 在写完 recErr 后
	// 兜底 closeDone。sync.Once 使两处 close 都安全。
	defer call.closeDone() //nolint:gocritic // unnecessaryDefer: 刻意保留 defer 形态,与上方注释所述 panic 兜底语义保持一致
}

// Invalidate 使缓存失效 (generation 递增使 in-flight 刷新结果被丢弃)。
//
// 同时清空 ongoingRefresh,使 Invalidate 之后到达的 Get 请求不再等待那条已在飞的旧刷新
// (旧刷新结果会因 generation 不匹配被 commitRefresh 丢弃),而是立即发起一次新的刷新。
// 配合 commitRefresh 的"只清自己 in-flight 槽"逻辑,旧刷新完成时不会误清新 call 的槽位。
func (s *CachedResultSupplier[T]) Invalidate() {
	s.mu.Lock()
	s.cachedResult = nil
	s.ongoingRefresh = nil
	s.generation++
	s.lastRefreshFailure = time.Time{}
	s.consecutiveFailures = 0
	s.mu.Unlock()
}

// ErrStaleCredentialReturned 返回已过期凭证时的错误信号。
//
// 调用方可选择忽略此错误继续使用旧值，或据此触发降级逻辑。
var ErrStaleCredentialReturned = errors.NewCacheError(
	constants.CachedResultStale,
	"cached credential is stale; a refresh was attempted but failed, the old value is returned for fallback",
	nil,
)

// ErrRefreshInBackoff 退避窗口内的刷新被短路返回错误。
//
// 触发点:GetWithContext 的 BLOCK expired 分支检测到 inStaleBackoff(上次刷新
// 失败后 10s 退避窗未过)时返回。BLOCK 硬保证"不返回过期值"仍成立(返回错误
// 而非旧值);fast-fail 让调用方立即拿到错误自决重试,而非逐请求阻塞打 IdP
// 致雪崩。调用方可 errors.Is(err, ErrRefreshInBackoff) 区分"退避中稍后重试"
// 与"硬刷新失败",便于侧的重试策略。退避窗固定 10s(复用 inStaleBackoff)。
var ErrRefreshInBackoff = errors.NewCacheError(
	constants.CachedRefreshInBackoff,
	"credential refresh is in backoff window after recent failure; retry later",
	nil,
)

// ErrRefreshInvalidated 刷新被 Invalidate 打断时的错误信号。
//
// commitRefresh 检测到 generation 不匹配（期间发生过 Invalidate）时，
// leader 与 waiter 不应拿到一个 stale-generation 的成功结果；
// 用此错误告知调用方刷新已失效、应当重试，而不是返回过期或空凭证。
var ErrRefreshInvalidated = errors.NewCacheError(
	constants.ConcurrentOperationFailed,
	"refresh result was invalidated by a concurrent Invalidate before commit",
	nil,
)

// ErrNilRefreshResult refreshFunc 返回 (nil, nil) 时的错误信号。
//
// (nil result, nil err) 会让调用方解引用 result.Value panic；
// safeRefresh 统一将其归一化为非 nil 错误，避免 nil-pointer deref。
var ErrNilRefreshResult = errors.NewCacheError(
	constants.UnexpectedError,
	"refresh function returned nil result without error",
	nil,
)

// ErrInvalidStaleValueBehavior staleValueBehavior 取值不在 BLOCK/ALLOW/REFRESH 之内。
//
// expired/stale switch 的 default 分支返回此错误，避免未知行为 fall-through 后
// 把过期凭证当成功返回。
var ErrInvalidStaleValueBehavior = errors.NewCacheError(
	constants.InvalidStaleValueBehavior,
	"unknown staleValueBehavior, must be one of BLOCK, ALLOW, REFRESH",
	nil,
)
