package factory

import (
	"context"
	"sync"
	"time"

	"github.com/cloud-idaas/idaas-go-core-sdk/cache"
	"github.com/cloud-idaas/idaas-go-core-sdk/config"
	"github.com/cloud-idaas/idaas-go-core-sdk/constants"
	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
	"github.com/cloud-idaas/idaas-go-core-sdk/errors"
	"github.com/cloud-idaas/idaas-go-core-sdk/http"
	"github.com/cloud-idaas/idaas-go-core-sdk/internal/implementation"
	"github.com/cloud-idaas/idaas-go-core-sdk/internal/implementation/authentication"
	"github.com/cloud-idaas/idaas-go-core-sdk/logger"
	"github.com/cloud-idaas/idaas-go-core-sdk/provider"
	"github.com/cloud-idaas/idaas-go-core-sdk/util"
)

// IDaaSCredentialProviderFactory 凭证提供者工厂，按 canonicalScope 维度注册并缓存 provider。
type IDaaSCredentialProviderFactory struct {
	mu          sync.RWMutex
	initialized bool
	config      *config.IDaaSClientConfig
	httpClient  http.HttpClient
	// httpClientOverride 允许外部注入自定义 HTTP client。
	// Initialize 时若已设置则跳过内部创建，直接使用注入的实例。
	httpClientOverride http.HttpClient

	// loggerOverride 宿主注入的 logger 实例。Initialize 期的
	// 安全降级 WARN 等日志优先用它;未注入时回退 logger.Default() 兜底。
	// 与后续阶段(logger ctx 透传 sweep) 正交:此处管 logger 实例注入,
	// 那里管 ctx 参数透传,两者不冲突。
	loggerOverride logger.Logger

	// tlsEnforcement 生产强制 TLS 模式("生产路径不可降级开启")。
	// opt-in:宿主显式 WithTLSEnforcement() 启用;默认 false(零回归,测试可关 TLS)。
	// 启用后 Initialize 检测 unsafeIgnoreSslCert=true 立即硬拒
	// (InsecureTLSDisallowed),库无法判"是否生产",故以 opt-in hook 给到生产宿主。
	tlsEnforcement bool

	// userCodeHandler Device Code 流程(RFC 8628)展示 user_code/验证 URI 的宿主回调。
	// 在 createHumanProvider 构造 HumanFederatedOidcTokenProvider
	// 后注入;provider 收到 device code 时调它而非写日志(避免一次性展示码进入
	// 持久化集中式日志被他人抢在合法用户前完成授权)。nil 时 provider 用默认
	// util.PrintUserCode(CLI stdout),零回归。
	userCodeHandler util.UserCodeHandler

	// tracePropagator 宿主注入的分布式 trace context 透传器(W3C TraceContext)。
	// Initialize 构造内部 DefaultHttpClient 时经 WithTracePropagator 下发;
	// 外部注入的 httpClientOverride 自行负责 trace 透传(见 WithHttpClient / WithTracePropagator 文档)。
	// nil 表示不注入(beta 默认,零回归)。
	tracePropagator http.TracePropagator

	// scope 维度注册表:key = cacheKey(instanceId, identityType, effectiveClientId, canonicalScope, providerKind)
	providers         map[string]provider.IDaaSCredentialProvider
	exchangeProviders map[string]provider.IDaaSTokenExchangeCredentialProvider

	// 预热 goroutine 生命周期:Reset 时先 cancel + 等待预热 goroutine 退出,
	// 再 Close provider,避免 Close 与预热 goroutine 读写同一 provider 的 supplier 竞态。
	warmupCancel context.CancelFunc
	warmupDone   chan struct{}

	// baseCtx 是工厂级宿主生命周期 ctx:Initialize 时创建,
	// Reset 时取消。经 WithBaseContext 注入每个 provider 的 supplier,使其后台
	// worker(leader 同步 worker / async worker)能感知宿主关闭、取消尚未完成的刷新。
	// 默认满足(非 opt-in)。生产路径非 nil;直接构造(测试) 未注入时
	// supplier.effectiveBaseContext 回退 context.Background 零回归。
	baseCtx    context.Context
	baseCancel context.CancelFunc

	// initGeneration 在每次 Initialize 时递增、每次 Reset 时递增。
	// warmupCancel/warmupDone 在同一临界区内注册,且 Reset 能原子摘取。
	// provider 注册时校验 generation 未变,防止旧 config 的 provider 写入新 cache。
	initGeneration uint64

	// GA 扩展点:token 生命周期事件 listener。
	// 独立于 mu 的锁,避免 notify 持快照时与 provider 缓存读写互相阻塞。
	listenersMu sync.RWMutex
	listeners   []TokenListener

	// 有界事件队列,替代每次 forEachListener 的 unbounded go func()。
	// 单 worker goroutine 从 channel 消费事件,channel 满时 drop-and-warn,
	// 防止 listener 回调阻塞时 goroutine 无限堆积耗尽宿主资源。
	eventQueue chan eventTask
	eventOnce  sync.Once
}

var (
	factoryInstance *IDaaSCredentialProviderFactory
	factoryOnce     sync.Once
)

// defaultWarmupTimeout 是 Init 预热阶段拉取凭证的超时上限。
// 取 60s (6x HTTP 默认读超时 DefaultReadTimeoutMs=10s),给元数据服务 +
// token endpoint 串联调用以及慢 CLIENT token 请求留足余量,同时避免启动期被单个慢请求
// 无限拖死:过短的超时会截断合法的慢请求(如 readTimeout=60s 的 CLIENT token)并通过
// singleflight 毒化后续 GetCredential。HUMAN identityType 的预热被跳过(device flow
// 是交互式的,不该用短超时预热),因此此超时仅影响非 HUMAN 路径。
const defaultWarmupTimeout = 60 * time.Second

// GetInstance 获取单例工厂实例。
//
// Deprecated: 自 v0.1.0 起改为包级函数 factory.Init / factory.InitWithConfig,
// 与 Java IDaaSCredentialProviderFactory.init() / Python IDaaSCredentialProviderFactory.init()
// 在调用形态上对齐。本方法保留为薄壳一个小版本,后续将移除。
func GetInstance() *IDaaSCredentialProviderFactory {
	factoryOnce.Do(func() {
		factoryInstance = &IDaaSCredentialProviderFactory{
			providers:         make(map[string]provider.IDaaSCredentialProvider),
			exchangeProviders: make(map[string]provider.IDaaSTokenExchangeCredentialProvider),
		}
	})
	return factoryInstance
}

// WithHttpClient 注入自定义 HTTP client。
//
// 允许外部消费者注入自定义或 mock HTTP client，与 Java SDK 的构造器注入对齐。
// 必须在 Initialize 之前调用。传入 nil 等同于不调用（使用 SDK 内部创建的 client）。
func (f *IDaaSCredentialProviderFactory) WithHttpClient(client http.HttpClient) *IDaaSCredentialProviderFactory {
	f.mu.Lock()
	f.httpClientOverride = client
	f.mu.Unlock()
	return f
}

// WithLogger 注入宿主 logger 实例。
// Initialize 期的安全降级 WARN(unsafeIgnoreSslCert / allowInsecureEndpoint)与
// GA 字段忽略提示优先用它;未注入时回退 logger.Default() 兜底。必须在 Initialize
// 之前调用。传入 nil 等同于不调用(使用 Default)。
//
// Experimental:beta 阶段接入;与后续阶段(ctx 透传 sweep,GA 前) 正交。
func (f *IDaaSCredentialProviderFactory) WithLogger(l logger.Logger) *IDaaSCredentialProviderFactory {
	f.mu.Lock()
	if l != nil {
		f.loggerOverride = l
	}
	f.mu.Unlock()
	return f
}

// WithTLSEnforcement 启用生产强制 TLS 模式("生产路径不可降级开启")。
// 启用后 Initialize 检测 unsafeIgnoreSslCert=true 立即返回
// InsecureTLSDisallowed 错误,不让生产路径降级关闭证书校验。
// 库无法判定"是否生产",故以 opt-in hook 给到生产宿主显式启用;默认不启用(零回归,
// 测试/mock server 场景仍可关 TLS)。必须在 Initialize 之前调用。
//
// Experimental:beta 阶段接入;GA 前若 enforcement 模型调整会变更。
func (f *IDaaSCredentialProviderFactory) WithTLSEnforcement() *IDaaSCredentialProviderFactory {
	f.mu.Lock()
	f.tlsEnforcement = true
	f.mu.Unlock()
	return f
}

// WithUserCodeHandler 注入 Device Code 流程(RFC 8628)的 user_code 展示回调
// 。handler 在 createHumanProvider 构造 HumanFederatedOidcTokenProvider
// 后注入到 provider;provider 在 device authorization 收到 code 时调用 handler 把
// verification URI 与 user_code 展示给最终用户,而非把它们写进结构化日志。
//
// user_code 是 RFC 8628 一次性短码(短生命周期、设计上人类可见),非长生命周期凭证,
// 但进入持久化集中式日志后可被他人抢在合法用户前完成 device 授权。默认 util.PrintUserCode
// (CLI 打印 stdout);服务端集成(无终端)必须注入 handler 覆盖以避免 code 走 stdout
// 被同机其他用户读到(side-effect)。必须在 Initialize 之前调用,传入 nil 等同
// 于不调用(使用默认 PrintUserCode)。
//
// Experimental:beta 阶段接入;GA 前若 device flow 展示协议调整会变更签名。
func (f *IDaaSCredentialProviderFactory) WithUserCodeHandler(h util.UserCodeHandler) *IDaaSCredentialProviderFactory {
	f.mu.Lock()
	if h != nil {
		f.userCodeHandler = h
	}
	f.mu.Unlock()
	return f
}

// WithTracePropagator 注入分布式 trace context 透传器(W3C TraceContext)。
// 注入后,SDK 向 token endpoint / IMDS / OIDC provider 的出站请求会携带 traceparent,
// 使凭证获取这一跳关联到宿主应用的分布式 trace,避免在 IdP 侧断链。
//
// 必须在 Initialize 之前调用。传入 nil 等同于不调用(使用 beta 默认,不注入,零回归)。
// SDK 不内置 OTel 依赖;宿主注入 OTel propagator 时需写一行 adapter(见 http.TracePropagator 文档)。
//
// 注意:仅对 SDK 内部构造的 DefaultHttpClient 生效;若同时使用 WithHttpClient 注入
// 自定义 client,该 client 的 trace 透传由调用方自行配置(自定义 client 可选实现
// http.HttpClient 时自行在 ExecuteContext 内注入 trace 头)。
//
// Experimental:beta 阶段接入;GA 前若 propagator 接口扩展会保持向后兼容。
func (f *IDaaSCredentialProviderFactory) WithTracePropagator(p http.TracePropagator) *IDaaSCredentialProviderFactory {
	f.mu.Lock()
	if p != nil {
		f.tracePropagator = p
	}
	f.mu.Unlock()
	return f
}

// effectiveLogger 返回注入的 logger 或 Default 兜底。锁内快照后释放再返回,
// 避免调用方持锁记日志与 WithLogger 写互相阻塞。
func (f *IDaaSCredentialProviderFactory) effectiveLogger() logger.Logger {
	f.mu.RLock()
	l := f.loggerOverride
	f.mu.RUnlock()
	if l == nil {
		return logger.Default()
	}
	return l
}

// Initialize 初始化工厂。
//
// 幂等:已初始化时记录 INFO 并直接返回 nil,不重建任何东西。
// 显式重置走 Reset()(与 Python reset() 对齐)。
func (f *IDaaSCredentialProviderFactory) Initialize(cfg *config.IDaaSClientConfig) error {
	if cfg == nil {
		return errors.NewConfigError(constants.ClientConfigurationNotFound, "client configuration is nil", nil)
	}

	f.mu.RLock()
	if f.initialized {
		f.mu.RUnlock()
		f.effectiveLogger().Info(context.Background(),
			"factory already initialized, skipping",
			"event", "factory.init", "status", "idempotent_skip")
		return nil
	}
	// 在 RLock 内快照 httpClientOverride / loggerOverride / tlsEnforcement,避免释放锁后
	// 无锁读与 WithHttpClient/WithLogger/WithTLSEnforcement/Reset 的写操作产生数据竞争。
	httpClientOverride := f.httpClientOverride
	loggerOverride := f.loggerOverride
	tlsEnforcement := f.tlsEnforcement
	tracePropagator := f.tracePropagator
	f.mu.RUnlock()

	// 在副本上做 Defaulting / Normalize，不修改调用方传入的 cfg。
	cfg = cloneConfig(cfg)

	// Defaulting: 对未设置的 HTTP 超时填充默认值。
	// 生命周期: Load → Defaulting → Normalize → Validate。
	applyConfigDefaults(cfg)

	// Normalize 必须在 Validate **之前**:校验器对 endpoint 执行 https 硬失败。
	normalizeEndpoints(cfg)

	validator := config.NewConfigValidator()
	if err := validator.Validate(cfg); err != nil {
		return err
	}

	// "生产路径不可降级开启":宿主显式 opt-in WithTLSEnforcement()
	// 后,unsafeIgnoreSslCert=true 立即硬拒(在 httpClient 构造前,确保不创建无 TLS 校验
	// 的 client)。库无法判定"是否生产",故以 opt-in hook 给到生产宿主;默认不启用(零回归)。
	// 用顶部 RLock 内快照的 tlsEnforcement,避免与 WithTLSEnforcement 写竞态。
	if tlsEnforcement && cfg.HttpConfiguration != nil && cfg.HttpConfiguration.UnsafeIgnoreSSLCert {
		return errors.NewConfigError(
			constants.InsecureTLSDisallowed,
			"TLS certificate verification cannot be disabled (unsafeIgnoreSslCert=true) "+
				"when TLS enforcement mode is enabled (WithTLSEnforcement); "+
				"remove unsafeIgnoreSslCert from the configuration for production deployments",
			nil,
		)
	}
	// ID046: WithTLSEnforcement 仅硬拦 unsafeIgnoreSslCert 却放行 allowInsecureEndpoint,
	// 后者让 OAuth2 凭证经明文 HTTP 传输,泄密面比关闭证书校验更广(被动抓包即可)。
	// 生产强制 TLS 模式下二者都应硬拒:证书校验不得关、端点不得降级为 http。
	if tlsEnforcement && cfg.AllowInsecureEndpoint {
		return errors.NewConfigError(
			constants.InsecureTLSDisallowed,
			"insecure HTTP endpoints are not allowed (allowInsecureEndpoint=true) "+
				"when TLS enforcement mode is enabled (WithTLSEnforcement); "+
				"remove allowInsecureEndpoint from the configuration for production deployments",
			nil,
		)
	}

	// 安全降级告警:证书校验关闭或 http 端点放行时,每次 init 打 WARN。
	// 这些开关降低安全等级,必须留痕,否则排障时无从得知"为什么 SDK 行为变了"。
	// 用注入的 logger(顶部 RLock 快照 loggerOverride,未注入时 Default 兜底)。
	// Initialize 已就绪幂等校验在前,此处每次真正初始化仅执行一次,不会随多次 Validate 刷屏。
	initLog := loggerOverride
	if initLog == nil {
		initLog = logger.Default()
	}
	if cfg.HttpConfiguration != nil && cfg.HttpConfiguration.UnsafeIgnoreSSLCert {
		initLog.Warn(context.Background(),
			"TLS certificate verification is DISABLED (unsafeIgnoreSslCert=true) — "+
				"this is insecure and should only be used for local testing",
			"event", "factory.init", "status", "security_downgrade",
			"flag", "unsafeIgnoreSslCert")
	}
	if cfg.AllowInsecureEndpoint {
		initLog.Warn(context.Background(),
			"insecure HTTP endpoints are ALLOWED (allowInsecureEndpoint=true) — "+
				"OAuth2 credentials will be sent over plaintext connections",
			"event", "factory.init", "status", "security_downgrade",
			"flag", "allowInsecureEndpoint")
	}

	// GA 预留字段在 beta 阶段仅解析、不生效。配置中显式设置却不打 WARN,
	// 调用方会误以为已生效(如设 failureMode=FAIL_OPEN 期望降级行为变化),到 GA 前才
	// 发现没起作用。这里逐字段提示"已解析但当前版本忽略",与 config 字段注释口径一致。
	// 注:staleValueBehavior 已在本次接入实际生效(由 effectiveStaleValueBehavior 下传到
	// supplier),不再列入"忽略"清单;failureMode 仍待 GA 映射。
	if cfg.FailureMode != "" {
		initLog.Warn(context.Background(),
			"failureMode is parsed but ignored in beta (degradation is controlled by staleValueBehavior, which is now active); "+
				"failureMode mapping will take effect in GA",
			"event", "factory.init", "status", "ga_field_ignored", "field", "failureMode",
			"value", string(cfg.FailureMode))
	}
	if cfg.MetricsEnabled {
		initLog.Warn(context.Background(),
			"metricsEnabled is parsed but ignored in beta (metrics recorder is always Noop); "+
				"it will take effect in GA",
			"event", "factory.init", "status", "ga_field_ignored", "field", "metricsEnabled")
	}
	if cfg.LogLevel != "" {
		initLog.Warn(context.Background(),
			"logLevel is parsed but ignored in beta (log level is controlled by the injected Logger); "+
				"it will take effect in GA",
			"event", "factory.init", "status", "ga_field_ignored", "field", "logLevel",
			"value", cfg.LogLevel)
	}

	var httpClient http.HttpClient
	// 若外部已注入 HTTP client，优先使用注入的实例（使用 RLock 内快照的值）。
	switch {
	case httpClientOverride != nil:
		// 外部注入的 client 自行负责 trace 透传(见 WithTracePropagator 文档)。
		httpClient = httpClientOverride
	case cfg.HttpConfiguration != nil:
		dhc := http.NewDefaultHttpClientWithOptions(
			cfg.HttpConfiguration.ConnectTimeout,
			cfg.HttpConfiguration.ReadTimeout,
			cfg.HttpConfiguration.UnsafeIgnoreSSLCert,
		)
		if tracePropagator != nil {
			dhc.WithTracePropagator(tracePropagator)
		}
		httpClient = dhc
	default:
		dhc := http.NewDefaultHttpClient(0, 0)
		if tracePropagator != nil {
			dhc.WithTracePropagator(tracePropagator)
		}
		httpClient = dhc
	}

	// 锁内只做"建对象 + 登记"（纯内存）→ 释放锁 → 锁外预热
	f.mu.Lock()
	// 双重检查。并发 Initialize 时只有第一个登记成功的生效，
	// 后到者不得覆盖已登记的 config / provider 缓存。
	if f.initialized {
		f.mu.Unlock()
		if closer, ok := httpClient.(http.ResourceCloser); ok && httpClient != f.httpClientOverride {
			closer.CloseIdleConnections()
		}
		logger.Default().Info(context.Background(),
			"factory already initialized, skipping",
			"event", "factory.init", "status", "idempotent_skip")
		return nil
	}
	f.config = cfg
	f.httpClient = httpClient
	f.providers = make(map[string]provider.IDaaSCredentialProvider)
	f.exchangeProviders = make(map[string]provider.IDaaSTokenExchangeCredentialProvider)
	// 工厂级 baseCtx:随本次 Initialize 创建,随 Reset 取消;注入每个 provider 的
	// supplier。在临界区内创建保证 Reset 摘取时见到正确句柄。
	f.baseCtx, f.baseCancel = context.WithCancel(context.Background())
	f.initialized = true
	// 递增 initGeneration,使后续 warmup 注册和 provider 注册时
	// 能检测到 Reset/re-Initialize 是否在期间发生过。
	f.initGeneration++
	myGen := f.initGeneration
	f.mu.Unlock()

	// 安装刷新事件 hook，把 supplier 的刷新生命周期事件转发给
	// 注册的 TokenListener。hook 是包级可变状态，Reset 时清除。
	// 放在 mu 解锁后安装，避免在临界区内调用 cache 包；hook 派发自身无锁竞争。
	cache.SetRefreshObserverHook(f.dispatchRefreshEvent)

	// 预热:为默认 scope 建 provider 并触发一次 GetCredentialWithContext。
	// 仅建 provider 不取凭证无法填充 CachedResultSupplier,首次真实请求仍走冷启动路径;
	// 此处显式拉取一次凭证以预热缓存,把网络延迟前移到启动期。
	// 预热在后台 goroutine 中执行:
	// - Initialize 立即返回,符合"lenient / non-blocking"语义,避免启动期被网络 IO 拖死;
	// - CachedResultSupplier 内部 singleflight 保证:若预热尚未完成时首个真实请求到达,
	// 两者合并为同一次刷新,不会产生双倍 IdP 调用。
	// 预热失败只告警不阻断,避免启动期网络抖动导致进程无法启动。
	//
	// cfg.Scope == "" 是合法配置(validator 允许,使用默认 scope),
	// 无论 scope 是否为空都预热(createCredentialProviderByScope 内部已对空 scope
	// 回落默认 scope),避免空 scope 首次请求走冷启动。
	// HUMAN identityType 的 device flow 是交互式的,不该用短超时预热;
	// 跳过 HUMAN 预热,避免超时截断交互流程并毒化 singleflight。
	identityType := cfg.AuthnConfiguration.IdentityType
	if identityType != enums.AuthenticationIdentityHuman {
		warmupScope := cfg.Scope
		if p, err := f.GetIDaaSCredentialProviderByScope(warmupScope); err != nil {
			logger.Default().Warn(context.Background(),
				"prefetch failed during init (non-blocking)",
				"event", "factory.prefetch", "status", "failed",
				"error", err.Error())
		} else {
			// 在同一临界区内注册 warmupCancel/warmupDone 并启动 goroutine,
			// 确保 Reset 能原子摘取 handles;若 generation 已变(Reset 发生),取消
			// 刚创建的 ctx 不注册,避免旧 warmup 泄漏。
			baseCtx, baseCancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			f.mu.Lock()
			if f.initGeneration != myGen || !f.initialized {
				// Reset 已在期间发生:不注册,直接取消。
				f.mu.Unlock()
				baseCancel()
				return nil
			}
			f.warmupCancel = baseCancel
			f.warmupDone = done
			// go 语句非阻塞,在锁内启动确保 Reset 摘取后 cancel 能立即通知 goroutine。
			go func(p provider.IDaaSCredentialProvider, done chan struct{}, baseCtx context.Context) {
				// 顶层 recover 兜住整段 goroutine：plugin/attested-document provider
				// 实现里的 panic 不得击穿宿主进程（可用性硬约束）。与 cache async refresh、
				// non_blocking prefetch、token_listener 三个 goroutine 启动点保持一致契约。
				// 置于 defer close(done) 之前：LIFO 下 recover 最后执行，确保 panic 时
				// close(done) 仍先触发，Reset 的 <-warmupDone 不会卡死。
				defer func() {
					if r := recover(); r != nil {
						logger.Default().Error(context.Background(),
							"warmup goroutine panic recovered",
							"event", "factory.prefetch", "status", "panic", "error", r)
					}
				}()
				defer close(done)
				warmupCtx, cancel := context.WithTimeout(baseCtx, defaultWarmupTimeout)
				defer cancel()
				if _, err := p.GetCredentialWithContext(warmupCtx); err != nil {
					logger.Default().Warn(context.Background(),
						"prefetch failed during init (non-blocking)",
						"event", "factory.prefetch", "status", "failed",
						"error", err.Error())
				}
			}(p, done, baseCtx)
			f.mu.Unlock()
		}
	}

	return nil
}

// Reset 重置工厂状态 (与 Python reset() 对齐)。
//
// 仅用于测试 / CLI 场景。清除 initialized 标志、config、httpClient 和所有 provider 缓存,
// 使下一次 Initialize 可以用新配置重新初始化。
func (f *IDaaSCredentialProviderFactory) Reset() {
	f.mu.Lock()
	// 快照待清理的资源,锁内只做纯内存的清空,Close 在锁外执行:
	// 注入的 PrefetchStrategy.Close 可能 wg.Wait(阻塞),不应在 f.mu 持有期间进行。
	httpClient := f.httpClient
	providers := f.providers
	exchangeProviders := f.exchangeProviders
	// 清除 cache 包级观察 hook,避免 Reset 后旧 factory 实例(或新 Initialize
	// 之前)仍向已失效的 listener 快照派发事件;Initialize 时重新安装。
	cache.SetRefreshObserverHook(nil)

	// 原子摘取 warmup handles:在清除 initialized 的同一临界区内
	// 抓取 warmupCancel/warmupDone 并置 nil,确保并发 Initialize 无法覆盖旧 handles
	// 导致旧 warmup goroutine 泄漏。同时递增 initGeneration 使任何正在进行的
	// warmup 注册或 provider 注册检测到 mismatch 并丢弃。
	warmupCancel := f.warmupCancel
	warmupDone := f.warmupDone
	f.warmupCancel = nil
	f.warmupDone = nil
	// 摘取 baseCancel:取消所有 supplier 后台 worker,
	// 使其在 provider Close 之前/期间收到取消信号停止刷新。置 nil 防止
	// 并发 Initialize 误用旧句柄。新 Initialize 会创建新 baseCtx。
	baseCancel := f.baseCancel
	f.baseCtx = nil
	f.baseCancel = nil
	f.initGeneration++

	f.initialized = false
	f.config = nil
	f.httpClient = nil
	f.httpClientOverride = nil
	f.providers = make(map[string]provider.IDaaSCredentialProvider)
	f.exchangeProviders = make(map[string]provider.IDaaSTokenExchangeCredentialProvider)
	f.mu.Unlock()

	// Reset 同步清空 f.listeners:重新 Initialize 后,旧生命周期的 TokenListener
	// 不应留在切片中接收新工厂的刷新事件,否则造成跨生命周期事件串扰(测试间复用工厂实例、
	// CLI 多次切换配置时尤其明显)。cache 包级观察 hook 已在上方置 nil,这里同步清空
	// 本工厂注册的 listener,使下一次 Initialize 从干净状态起步。用 listenersMu
	// 而非 f.mu 保护(与 AddTokenListener/dispatch 的锁一致),且在 f.mu 释放后执行
	// 避免嵌套持锁。
	f.listenersMu.Lock()
	f.listeners = f.listeners[:0]
	f.listenersMu.Unlock()

	// 清理 HTTP transport 空闲连接。
	if httpClient != nil {
		if closer, ok := httpClient.(http.ResourceCloser); ok {
			closer.CloseIdleConnections()
		}
	}

	// 先取消并等待预热 goroutine 退出,再 Close provider。
	// 否则预热 goroutine 可能正在读写 provider 的 supplier,与 Close 形成 data race。
	if warmupCancel != nil {
		warmupCancel()
		if warmupDone != nil {
			select {
			case <-warmupDone:
			case <-time.After(2*defaultWarmupTimeout + 2*time.Second):
				// 等待预热 goroutine 退出的超时取 2×defaultWarmupTimeout+2s:预热 goroutine 的
				// GetCredentialWithContext 内部走 doRefresh,后者用 detached context
				// (asyncRefreshTimeout=2min),warmupCtx 取消无法传播到实际 refresh,
				// 需覆盖最坏情况(2min)而非 defaultWarmupTimeout+2s=62s。
				// 超时后不阻塞 Reset,继续清理;supplier.Close 内部用锁保护,语义安全。
			}
		}
	}

	// 取消工厂级 baseCtx:通知所有 supplier 后台 worker
	// (leader 同步 worker / async worker / Azure fetch worker)宿主正在关闭,
	// 取消尚未完成的刷新。放在 warmup 等待之后、provider Close 之前:
	// worker 收到取消后 promptly 退出,与 Close 的资源释放不竞态。
	if baseCancel != nil {
		baseCancel()
	}

	// 释放 provider 持有的后台资源(注入的 PrefetchStrategy / supplier goroutine)。
	// 注入 NonBlockingPrefetchStrategy 的 provider 若不 Close,Reset 后其 ticker/goroutine 仍泄漏。
	// 实现了 io.Closer 的 provider(机器凭证经 AbstractRefreshedCredentialProvider、
	// human provider 自带 Close)会被关闭;token-exchange provider 不持缓存,无 Close → 跳过。
	for _, p := range providers {
		closeProviderIfCloser(p)
	}
	for _, p := range exchangeProviders {
		closeProviderIfCloser(p)
	}
}

// closeProviderIfCloser 在 v 实现了 Close() error 时调用其 Close,忽略返回值。
// 用 interface 类型断言而非 io.Closer,避免在接口定义中强制要求所有 provider 实现 Close。
func closeProviderIfCloser(v interface{}) {
	type closer interface {
		Close() error
	}
	if c, ok := v.(closer); ok {
		_ = c.Close()
	}
}

// normalizeEndpoints 就地归一化配置中的全部 endpoint。
func normalizeEndpoints(cfg *config.IDaaSClientConfig) {
	// 传入 allowInsecureEndpoint，使逃生舱对文件加载的配置也生效。
	// 之前 NormalizeEndpoint 无条件提升 http→https，导致 allowInsecureEndpoint=true
	// + http:// 端点的组合在 validator 看到时已经是 https://，逃生舱失效。
	allowInsecure := cfg.AllowInsecureEndpoint

	fields := []struct {
		name string
		ptr  *string
	}{
		{"issuer", &cfg.IssuerEndpoint},
		{"tokenEndpoint", &cfg.TokenEndpoint},
		{"deviceAuthorizationEndpoint", &cfg.DeviceAuthorizationEndpoint},
		{"developerApiEndpoint", &cfg.DeveloperApiEndpoint},
		{"openApiEndpoint", &cfg.OpenApiEndpoint},
	}
	for _, f := range fields {
		original := *f.ptr
		normalized := util.NormalizeEndpointWithSecurity(original, allowInsecure)
		if normalized == original {
			continue
		}
		*f.ptr = normalized
		// 仅记录 scheme://host/path,剥离 userinfo、query、fragment。
		// URL 校验允许 userinfo 和 query;记录原始值会泄露嵌在 URL 中的凭证,
		// 如 https://user:secret@host/token?access_token=x。
		logger.Default().Warn(context.Background(),
			"endpoint normalized",
			"event", "config.normalize", "status", "success",
			"field", f.name,
			"from", util.SanitizeEndpointForLog(original),
			"to", util.SanitizeEndpointForLog(normalized))
	}
}

// cloneConfig 复制配置，Initialize 内的 Defaulting / Normalize 只作用于副本。
// 被修改的嵌套结构（AuthnConfiguration / HttpConfiguration）一并复制；其余字段为值类型。
func cloneConfig(cfg *config.IDaaSClientConfig) *config.IDaaSClientConfig {
	c := *cfg
	if cfg.AuthnConfiguration != nil {
		authn := *cfg.AuthnConfiguration
		c.AuthnConfiguration = &authn
	}
	if cfg.HttpConfiguration != nil {
		httpConf := *cfg.HttpConfiguration
		c.HttpConfiguration = &httpConf
	}
	return &c
}

// applyConfigDefaults 对配置中未设置的值填充默认值 (Defaulting 阶段)。
//
// 目前覆盖:
// - HttpConfiguration 为 nil → 创建默认配置 (5000/10000/false)
// - HttpConfiguration 超时为 0 → 填充默认值 (5000/10000)
// - AuthnConfiguration.IdentityType 为空 → CLIENT (与 Java 默认值一致)
func applyConfigDefaults(cfg *config.IDaaSClientConfig) {
	if cfg.AuthnConfiguration != nil && cfg.AuthnConfiguration.IdentityType == "" {
		cfg.AuthnConfiguration.IdentityType = enums.AuthenticationIdentityClient
	}
	if cfg.HttpConfiguration == nil {
		cfg.HttpConfiguration = config.DefaultHttpConfiguration()
		return
	}
	cfg.HttpConfiguration.ApplyDefaults()
}

// buildCacheKey 构造带身份维度的缓存键。
//
// 格式:{instanceId}|{identityType}|{effectiveClientId}|{canonicalScope}|{providerKind}
// 其中 effectiveClientId 对 HUMAN 取 HumanAuthenticateClientId(含默认值回落),
// providerKind 区分 credential / token-exchange。
func (f *IDaaSCredentialProviderFactory) buildCacheKey(
	identityType enums.AuthenticationIdentityEnum,
	canonicalScope string,
	providerKind string,
) string {
	// 防御性 nil 检查，与其他方法的 nil guard 模式保持一致。
	if f.config == nil {
		return ""
	}
	effectiveClientId := f.config.ClientId
	if identityType == enums.AuthenticationIdentityHuman {
		humanClientId := f.config.AuthnConfiguration.HumanAuthenticateClientId
		if humanClientId == "" {
			humanClientId = constants.DefaultHumanAuthenticateClientId
		}
		effectiveClientId = humanClientId
	}
	return f.config.InstanceId + "|" +
		string(identityType) + "|" +
		effectiveClientId + "|" +
		canonicalScope + "|" +
		providerKind
}

// CreateCredentialProvider 创建凭证提供者。
// Deprecated: 使用 GetIDaaSCredentialProvider / GetIDaaSCredentialProviderByScope 替代。
func (f *IDaaSCredentialProviderFactory) CreateCredentialProvider() (provider.IDaaSCredentialProvider, error) {
	// 传空 scope，由 createCredentialProviderByScope 在读锁内回落到配置的默认 scope；
	// 不在这里直接读 f.config，否则工厂未初始化时会 nil 解引用而不是返回 NotInit。
	return f.GetIDaaSCredentialProviderByScope("")
}

// createCredentialProviderByScope 创建指定 scope 的凭证提供者。
// 构造用写锁(纯内存),查表用读锁,网络 IO 一律在锁外。
func (f *IDaaSCredentialProviderFactory) createCredentialProviderByScope(scope string) (provider.IDaaSCredentialProvider, error) {
	for {
		f.mu.RLock()
		if !f.initialized {
			f.mu.RUnlock()
			return nil, errors.NewConfigError(constants.IDaaSCredentialProviderFactoryNotInit, "Factory not initialized", nil)
		}

		identityType := f.config.AuthnConfiguration.IdentityType
		// 空 scope 等价于配置的默认 scope，保证缓存 key 与实际请求的 scope 一致。
		if scope == "" {
			scope = f.config.Scope
		}
		// HUMAN 空 scope 时 provider 构造器内部回退 DefaultScope,
		// factory 须在 cacheKey 前应用相同回退,避免空 scope 与显式 DefaultScope
		// 产生不同 cacheKey 却共享磁盘缓存 → 重复 provider / device flow 竞态。
		if scope == "" && identityType == enums.AuthenticationIdentityHuman {
			scope = authentication.DefaultScope
		}
		canonicalScope := util.CanonicalizeScope(scope)
		cacheKey := f.buildCacheKey(identityType, canonicalScope, "credential")

		if existing, ok := f.providers[cacheKey]; ok {
			f.mu.RUnlock()
			return existing, nil
		}
		cfg := f.config
		httpClient := f.httpClient
		// 快照 baseCtx(随 Reset 取消),锁外注入到 provider 的 supplier。
		// 锁内读取避免与 Reset 的 baseCancel 写竞态。
		snapBaseCtx := f.baseCtx
		// 快照 userCodeHandler,锁外注入到 human provider,避免与
		// WithUserCodeHandler 写竞态(nil 时 provider 用默认 PrintUserCode)。
		snapUserCodeHandler := f.userCodeHandler
		// 快照 initGeneration,锁外构造 provider 后在写锁内校验。
		// 若期间发生 Reset()+re-Initialize(newCfg),generation 不匹配 → 丢弃旧 provider。
		snapGen := f.initGeneration
		f.mu.RUnlock()

		// 锁外构造 provider (纯内存,无网络 IO)
		var newProvider provider.IDaaSCredentialProvider
		var err error
		switch identityType {
		case enums.AuthenticationIdentityClient:
			newProvider, err = f.createMachineProvider(cfg, scope, httpClient, snapBaseCtx)
		case enums.AuthenticationIdentityHuman:
			// 把请求 scope 传给 human provider,使其 device-code 请求与
			// 磁盘缓存都按真实 scope 隔离,而非构造器硬编码 DefaultScope。
			newProvider, err = f.createHumanProvider(cfg, scope, httpClient, snapBaseCtx, snapUserCodeHandler)
		default:
			return nil, errors.NewConfigError(constants.UnsupportedIdentityType, "Unsupported identity type", nil)
		}
		if err != nil {
			return nil, err
		}

		// 锁内登记 (纯内存写)
		f.mu.Lock()
		// generation 校验:若期间 Reset/re-Initialize 发生,丢弃旧 config 的 provider。
		if f.initGeneration != snapGen || !f.initialized {
			// Factory 被 Reset/re-initialized：旧 config 构造的 provider 可能与新 config 不兼容。
			// 丢弃它（Close 若有），在新 config 下重新获取。
			closeProviderIfCloser(newProvider)
			if !f.initialized {
				f.mu.Unlock()
				return nil, errors.NewConfigError(constants.IDaaSCredentialProviderFactoryNotInit, "Factory was reset during provider creation", nil)
			}
			// 不在持写锁时递归调用(会 RLock 死锁——RWMutex 非重入),
			// 释放锁后 continue 重试。
			f.mu.Unlock()
			continue
		}
		// Double-check: 可能在此期间已有其他 goroutine 注册了同一 key
		if existing, ok := f.providers[cacheKey]; ok {
			f.mu.Unlock()
			return existing, nil
		}
		f.providers[cacheKey] = newProvider
		f.mu.Unlock()
		return newProvider, nil
	}
}

// createMachineProvider 创建请求指定 scope 的机器凭证提供者。
func (f *IDaaSCredentialProviderFactory) createMachineProvider(cfg *config.IDaaSClientConfig, scope string, httpClient http.HttpClient, baseCtx context.Context) (provider.IDaaSCredentialProvider, error) {
	p := implementation.NewIDaaSMachineCredentialProviderForScope(cfg, scope, effectiveStaleValueBehavior(cfg), httpClient)
	// 注入工厂级 baseCtx:supplier 后台 worker 据此感知宿主关闭。
	// baseCtx 由 Initialize 创建、Reset 取消;非 nil 时注入,否则留 nil(BACKGROUND 回退)。
	if baseCtx != nil {
		p.WithBaseContext(baseCtx)
	}
	return p, nil
}

// createHumanProvider 创建人类凭证提供者
func (f *IDaaSCredentialProviderFactory) createHumanProvider(cfg *config.IDaaSClientConfig, scope string, httpClient http.HttpClient, baseCtx context.Context, userCodeHandler util.UserCodeHandler) (provider.IDaaSCredentialProvider, error) {
	if cfg.DeviceAuthorizationEndpoint == "" {
		return nil, errors.NewConfigError(constants.DeviceAuthorizationEndpointNotFound, "Device authorization endpoint is required for human authentication", nil)
	}

	humanClientId := cfg.AuthnConfiguration.HumanAuthenticateClientId
	if humanClientId == "" {
		humanClientId = constants.DefaultHumanAuthenticateClientId
	}

	p := authentication.NewHumanFederatedOidcTokenProvider(
		cfg.InstanceId,
		humanClientId,
		cfg.TokenEndpoint,
		cfg.DeviceAuthorizationEndpoint,
		effectiveStaleValueBehavior(cfg),
		scope,
		httpClient,
	)
	// 注入工厂级 baseCtx:device flow 的 lazy supplier
	// (getOrCreateSupplier)据此时 baseCtx 在构造 supplier 时注入 WithBaseContext。
	if baseCtx != nil {
		p.WithBaseContext(baseCtx)
	}
	// 注入宿主 user_code handler:device authorization 收到
	// code 时经 handler 展示给最终用户,而非写进结构化日志。nil 时 provider
	// 用默认 util.PrintUserCode(零回归);服务端集成注入 handler 覆盖。
	// 入参是 RLock 内快照,避免与 WithUserCodeHandler 写竞态。
	if userCodeHandler != nil {
		p.WithUserCodeHandler(userCodeHandler)
	}
	return p, nil
}

// effectiveStaleValueBehavior 规范化配置的 staleValueBehavior:空值回退 REFRESH。
// config.Validator 已拦截非法非空值,这里只处理空值默认,与 beta 阶段各 provider
// 硬编码 StaleValueBehaviorRefresh 的行为一致,保证旧配置无感升级。
func effectiveStaleValueBehavior(cfg *config.IDaaSClientConfig) enums.StaleValueBehavior {
	if cfg.StaleValueBehavior == "" {
		return enums.StaleValueBehaviorRefresh
	}
	return cfg.StaleValueBehavior
}

// createTokenExchangeProviderByScope 创建指定 scope 的令牌交换提供者。
// PLUGIN 方式不注册 token-exchange provider (与 Java 一致)。
func (f *IDaaSCredentialProviderFactory) createTokenExchangeProviderByScope(scope string) (provider.IDaaSTokenExchangeCredentialProvider, error) {
	for {
		f.mu.RLock()
		if !f.initialized {
			f.mu.RUnlock()
			return nil, errors.NewConfigError(constants.IDaaSCredentialProviderFactoryNotInit, "Factory not initialized", nil)
		}

		// 与 credential 路径一致，空 scope 先回落到配置的默认 scope 再计算缓存 key，
		// 使 ByScope("") 与 ByScope(cfg.Scope) 命中同一个 provider。
		if scope == "" {
			scope = f.config.Scope
		}
		canonicalScope := util.CanonicalizeScope(scope)
		identityType := f.config.AuthnConfiguration.IdentityType
		cacheKey := f.buildCacheKey(identityType, canonicalScope, "exchange")

		if existing, ok := f.exchangeProviders[cacheKey]; ok {
			f.mu.RUnlock()
			return existing, nil
		}
		cfg := f.config
		httpClient := f.httpClient
		// 快照 initGeneration,锁外构造 provider 后在写锁内校验。
		snapGen := f.initGeneration
		f.mu.RUnlock()

		// PLUGIN 不支持 token-exchange (与 Java 一致)
		if cfg.AuthnConfiguration.AuthnMethod == enums.TokenAuthnMethodPlugin {
			return nil, errors.NewConfigError(constants.UnsupportedAuthenticationMethod,
				"Token exchange is not supported for PLUGIN authn method", nil)
		}
		// token exchange 需按 authnMethod 做客户端认证；HUMAN 可不配 authnMethod，
		// 此时在获取阶段直接报错，而不是等到 ExchangeToken 才失败。
		if cfg.AuthnConfiguration.AuthnMethod == "" {
			return nil, errors.NewConfigError(constants.AuthnConfigurationNotFound,
				"Token exchange requires authnMethod for client authentication", nil)
		}

		// 客户端认证材料由 provider 每次请求时按 authn method 构造。
		newProvider := implementation.NewIDaaSMachineTokenExchangeCredentialProvider(cfg, canonicalScope, httpClient)

		// 锁内登记
		f.mu.Lock()
		// generation 校验:若期间 Reset/re-Initialize 发生,丢弃旧 config 的 provider。
		if f.initGeneration != snapGen || !f.initialized {
			closeProviderIfCloser(newProvider)
			if !f.initialized {
				f.mu.Unlock()
				return nil, errors.NewConfigError(constants.IDaaSCredentialProviderFactoryNotInit, "Factory was reset during provider creation", nil)
			}
			// 不在持写锁时递归调用(会 RLock 死锁——RWMutex 非重入),
			// 释放锁后 continue 重试。
			f.mu.Unlock()
			continue
		}
		if existing, ok := f.exchangeProviders[cacheKey]; ok {
			f.mu.Unlock()
			return existing, nil
		}
		f.exchangeProviders[cacheKey] = newProvider
		f.mu.Unlock()
		return newProvider, nil
	}
}

// GetIDaaSCredentialProviderByScope 获取指定 scope 的凭证提供者。
// scope 经 CanonicalizeScope 规范化后作为缓存键。
func (f *IDaaSCredentialProviderFactory) GetIDaaSCredentialProviderByScope(scope string) (provider.IDaaSCredentialProvider, error) {
	return f.createCredentialProviderByScope(scope)
}

// GetIDaaSTokenExchangeCredentialProviderByScope 获取指定 scope 的令牌交换提供者。
func (f *IDaaSCredentialProviderFactory) GetIDaaSTokenExchangeCredentialProviderByScope(scope string) (provider.IDaaSTokenExchangeCredentialProvider, error) {
	return f.createTokenExchangeProviderByScope(scope)
}

// IsInitialized 检查是否已初始化
func (f *IDaaSCredentialProviderFactory) IsInitialized() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.initialized
}

// GetConfig 返回当前配置的深拷贝（供插件读取 instanceId / clientId / openApiEndpoint 等）。
// 返回 cloneConfig 副本而非原始指针,与 GetHttpConfig 的深拷贝语义对齐,
// 防止调用方就地修改 AuthnConfiguration/Scope 等字段污染已冻结的配置快照。
func (f *IDaaSCredentialProviderFactory) GetConfig() *config.IDaaSClientConfig {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.config == nil {
		return nil
	}
	return cloneConfig(f.config)
}

// GetDeveloperApiEndpoint 返回 Developer API 端点。
func (f *IDaaSCredentialProviderFactory) GetDeveloperApiEndpoint() string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.config == nil {
		return ""
	}
	return f.config.DeveloperApiEndpoint
}

// GetOpenApiEndpoint 返回 OpenAPI 端点 (用 OpenApi 分词,不复刻 Java 的 OpenApi 笔误)。
func (f *IDaaSCredentialProviderFactory) GetOpenApiEndpoint() string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.config == nil {
		return ""
	}
	return f.config.OpenApiEndpoint
}

// GetIDaaSInstanceId 返回实例 ID (IDaaS 大小写按规范)。
func (f *IDaaSCredentialProviderFactory) GetIDaaSInstanceId() string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.config == nil {
		return ""
	}
	return f.config.InstanceId
}

// GetClientId 返回 Client ID。
func (f *IDaaSCredentialProviderFactory) GetClientId() string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.config == nil {
		return ""
	}
	return f.config.ClientId
}

// GetHttpConfig 返回 HTTP 配置的深拷贝(对齐 Java HttpConfiguration.copy)。
func (f *IDaaSCredentialProviderFactory) GetHttpConfig() *config.HttpConfiguration {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.config == nil || f.config.HttpConfiguration == nil {
		return nil
	}
	// 深拷贝,防止调用方就地修改影响已冻结的配置快照
	hc := f.config.HttpConfiguration
	return &config.HttpConfiguration{
		ConnectTimeout:      hc.ConnectTimeout,
		ReadTimeout:         hc.ReadTimeout,
		UnsafeIgnoreSSLCert: hc.UnsafeIgnoreSSLCert,
	}
}
