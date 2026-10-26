package authentication

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cloud-idaas/idaas-go-core-sdk/cache"
	"github.com/cloud-idaas/idaas-go-core-sdk/constants"
	"github.com/cloud-idaas/idaas-go-core-sdk/credential"
	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
	sdkerrors "github.com/cloud-idaas/idaas-go-core-sdk/errors"
	"github.com/cloud-idaas/idaas-go-core-sdk/http"
	"github.com/cloud-idaas/idaas-go-core-sdk/logger"
	"github.com/cloud-idaas/idaas-go-core-sdk/oauth2"
	"github.com/cloud-idaas/idaas-go-core-sdk/util"
)

const (
	// MaxWaitIntervalSeconds Device Code 最大等待时间（秒）
	MaxWaitIntervalSeconds = 180
	// DefaultScope 默认 scope
	DefaultScope = "openid offline_access"
	// DefaultPollInterval 默认轮询间隔（秒）
	DefaultPollInterval = 5
	// MaxPollInterval Device Code 轮询间隔上界（秒）。
	// RFC 8628 的 interval 由 IdP 返回,理论上无上界;若 IdP 异常返回超大值(或多次
	// slow_down 累加),pollInterval 会增长到使单轮 sleep 超过剩余等待窗口,
	// 虽被 remaining 夹到无功能危害,但语义上不合理且掩盖 IdP 异常。这里设 30s
	// (6×DefaultPollInterval),兼顾 slow_down 降频诉求与合理轮询频率。
	MaxPollInterval = 30
)

// HumanFederatedOidcTokenProvider 人类联邦 OIDC Token 提供者 ( HUMAN)
// 支持 Device Code 流程和本地缓存复用
type HumanFederatedOidcTokenProvider struct {
	clientId                    string
	scope                       string
	tokenEndpoint               string
	deviceAuthorizationEndpoint string
	localHumanCachePath         string
	httpClient                  http.HttpClient
	oauth2Util                  *oauth2.OAuth2TokenUtil
	// staleBehavior 控制缓存进入 stale 窗口后的行为,由 factory 从配置注入,
	// 空值时 getSupplier 回退 REFRESH,与 beta 阶段硬编码默认一致。
	staleBehavior enums.StaleValueBehavior

	// supplier 负责缓存与刷新时机：token 有效期内直接返回缓存，过 PrefetchTime 异步刷新，
	// 进入 stale 后同步刷新，并发调用通过 singleflight 只触发一次 refresh。
	// 延迟创建，结构体字面量构造的 provider 也能使用。
	// 用 RWMutex 守护 supplier 字段的读写，替代原 sync.Once + bare read。
	// sync.Once.Do 的 happens-before 只对 Do 的调用方生效，Close 的 bare read
	// `if p.supplier != nil` 与 getSupplier 内的写存在 data race；RWMutex 让读路径
	// (热路径)走 RLock，写路径(初始化/Close)走 Lock，统一建立同步关系。
	supplierMu sync.RWMutex
	supplier   *cache.CachedResultSupplier[credential.IDaaSTokenResponse]

	// baseCtx 由 factory 注入,随 Reset 取消;在 getOrCreateSupplier
	// 构造 supplier 时经 WithBaseContext 注入,使 device flow 的后台刷新 worker
	// 能感知宿主关闭。nil(直接构造/测试)时 supplier 回退 Background 零回归。
	baseCtx context.Context

	// userCodeHandler 是 Device Code 流程(RFC 8628)展示 user_code/验证 URI 的宿主回调。
	// user_code 是一次性短码(设计上人类可见,非长生命周期凭证),
	// 经此 handler 走 stdout/宿主 UI 而非结构化日志,避免进入持久化集中式日志后被他人
	// 抢在合法用户前完成授权。默认 util.PrintUserCode(CLI 打印 stdout);服务端集成
	// 必须注入 handler 覆盖。SDK 不对宿主回调 recover(:宿主回调 panic 属宿主责任)。
	userCodeHandler util.UserCodeHandler

	// lastToken 是最近一次获取到的 token，供下一次 refresh 取 refresh_token；
	// nil 表示首次启动（先尝试本地缓存，再走 device flow）。tokenMu 不跨网络调用持有。
	tokenMu   sync.Mutex
	lastToken *credential.IDaaSTokenResponse
}

// WithBaseContext 注入宿主生命周期 ctx。
// 必须在首次取凭证前(factory 构造后、GetCredential 前)调用。
//
// Experimental:beta 阶段接入;GA 前若 baseCtx 语义统一化会调整注入层。
func (p *HumanFederatedOidcTokenProvider) WithBaseContext(ctx context.Context) *HumanFederatedOidcTokenProvider {
	p.baseCtx = ctx
	return p
}

// WithUserCodeHandler 注入 Device Code 流程(RFC 8628)的 user_code 展示回调
// 。handler 决定如何把 verification URI 与 user_code 展示给
// 最终用户(CLI 打印 stdout、服务端渲染 web 页等),并可选地调 util.OpenBrowser
// 打开浏览器(库边界 side-effect 由宿主决定,SDK 自身不主动打开)。
//
// 不注入时默认 util.PrintUserCode(CLI 打印 stdout);服务端集成(无终端)必须
// 覆盖以避免 user_code 走 stdout 被同机其他用户读到(side-effect)。
// SDK 不对宿主回调 recover(:宿主回调 panic 属宿主责任,不在库边界吞掉)。
//
// Experimental:beta 阶段接入;GA 前若 device flow 展示协议调整会变更签名。
func (p *HumanFederatedOidcTokenProvider) WithUserCodeHandler(h util.UserCodeHandler) *HumanFederatedOidcTokenProvider {
	if h == nil {
		return p
	}
	p.userCodeHandler = h
	return p
}

// sanitizeCacheSegment 把 instanceId/clientId 收敛为安全的缓存文件名片段。
//
// 这两个值来自配置;若含路径分隔符 "/" "\" 或为路径元分量 "." "..",直接拼进
// filepath.Join 会穿越 ~/.cloud_idaas/human-cache 目录(实测
// instanceId="../../../../tmp/pwn" 会落到 /tmp/pwn_client.json,可覆盖系统文件
// 或落到 world-writable 目录)。回退为输入的 sha256 前 16 字符(前缀 "id_"):
// 不含分隔符、不同非法输入互不覆盖、且不暴露原值。合法输入(无分隔符)原样返回,
// 兼容已落盘的缓存文件名。
//
// 构造函数另有 base-dir 包含校验作为纵深防御,即便本函数回归也不会逃出 baseDir。
func sanitizeCacheSegment(s string) string {
	if s != "" && s != "." && s != ".." && !strings.ContainsAny(s, "/\\") {
		return s
	}
	sum := sha256.Sum256([]byte(s))
	return "id_" + hex.EncodeToString(sum[:])[:16]
}

// scopeHashSuffix 返回 scope 维度的缓存文件名后缀。
//
// DefaultScope(经 CanonicalizeScope 归一比较)返回空串,保持旧文件名向后兼容已落盘缓存;
// 其它 scope 返回 "_s" + canonical scope 的 sha256 前 8 字符,使不同 scope 的磁盘令牌
// 物理隔离(不同 scope 的 token 权限/受众不同,复用会导致越权或鉴权失败)。
// 后缀只含 '_' 与十六进制字符,不含路径分隔符,无穿越风险;构造函数的 base-dir 包含
// 校验仍作为纵深防御。
func scopeHashSuffix(scope string) string {
	if util.CanonicalizeScope(scope) == util.CanonicalizeScope(DefaultScope) {
		return ""
	}
	sum := sha256.Sum256([]byte(util.CanonicalizeScope(scope)))
	return "_s" + hex.EncodeToString(sum[:])[:8]
}

// NewHumanFederatedOidcTokenProvider 创建 HumanFederatedOidcTokenProvider
//
// instanceId 用于隔离不同 IDaaS 实例的本地凭证缓存:同一 clientId 在不同实例下
// 拥有独立缓存文件,避免跨实例串用。空 instanceId 时回退到不带实例前缀的旧文件名
// (向后兼容已落盘的缓存)。
//
// scope 是 device-code 请求与磁盘缓存隔离维度。空 scope 回退 DefaultScope
// ("openid offline_access")。非默认 scope 的缓存文件名追加 scope 的短哈希片段,
// 保证不同 scope 不复用同一份磁盘令牌(DefaultScope 保持旧文件名,向后兼容已落盘缓存)。
func NewHumanFederatedOidcTokenProvider(
	instanceId string,
	clientId string,
	tokenEndpoint string,
	deviceAuthorizationEndpoint string,
	staleBehavior enums.StaleValueBehavior,
	scope string,
	httpClient http.HttpClient,
) *HumanFederatedOidcTokenProvider {
	// 接受调用方传入的 scope,空值回退 DefaultScope:
	// device-code 请求与缓存 key 都按真实 scope 区分,避免 scope 与实际令牌不一致。
	effectiveScope := scope
	if effectiveScope == "" {
		effectiveScope = DefaultScope
	}

	provider := &HumanFederatedOidcTokenProvider{
		clientId:                    clientId,
		scope:                       effectiveScope,
		tokenEndpoint:               tokenEndpoint,
		deviceAuthorizationEndpoint: deviceAuthorizationEndpoint,
		httpClient:                  httpClient,
		oauth2Util:                  oauth2.NewOAuth2TokenUtil(httpClient),
		staleBehavior:               staleBehavior,
		// user_code 经 handler 走 stdout 而非结构化日志,
		// 避免一次性展示码进入持久化集中式日志后被他人抢在合法用户前完成授权。
		// 默认 util.PrintUserCode(CLI);服务端集成须 WithUserCodeHandler 覆盖。
		userCodeHandler: util.PrintUserCode,
	}

	envPath := os.Getenv(constants.EnvHumanCredentialCachePathKey)
	if envPath != "" {
		provider.localHumanCachePath = envPath
	} else {
		// 默认路径：~/.cloud_idaas/human-cache/{instanceId}_{clientId}{_scopeSuffix}.json
		// 文件名带 instanceId 维度,确保不同实例的同 clientId 缓存互不覆盖。
		// instanceId 为空时(旧调用方)退化为 {clientId}{_scopeSuffix}.json,兼容已落盘文件。
		// instanceId/clientId 经 sanitizeCacheSegment 收敛为安全文件名片段:
		// 含路径分隔符或为路径元分量的输入会让 filepath.Join 穿越 human-cache 目录
		// (实测 instanceId="../../../../tmp/pwn" 会落到 /tmp/pwn_client.json)。
		// 非 DefaultScope 追加 scope 短哈希片段,不同 scope 的磁盘令牌隔离,
		// 避免请求 scope1 的 provider 复用 scope0 缓存的令牌。DefaultScope 不加后缀,
		// 向后兼容已落盘的旧缓存文件。
		homeDir, err := os.UserHomeDir()
		if err != nil {
			homeDir = "."
		}
		scopeSuffix := scopeHashSuffix(effectiveScope)
		iSeg := sanitizeCacheSegment(instanceId)
		cSeg := sanitizeCacheSegment(clientId)
		fileName := cSeg + scopeSuffix + ".json"
		if instanceId != "" {
			// instanceId/clientId 经 sanitizeCacheSegment 后下划线原样保留,会出现
			// (instanceId="a_b", clientId="c") 与 (instanceId="a", clientId="b_c")
			// 生成同一文件名 a_b_c.json 的歧义,导致不同实例/client 复用对方缓存令牌(越权风险)。
			// 故任一段含下划线时改用长度前缀编码 (len_i_iSeg_len_c_cSeg) 消除歧义;
			// 无下划线时保持原格式,兼容已落盘缓存文件。
			if strings.Contains(iSeg, "_") || strings.Contains(cSeg, "_") {
				fileName = fmt.Sprintf("%d_%s_%d_%s%s.json", len(iSeg), iSeg, len(cSeg), cSeg, scopeSuffix)
			} else {
				fileName = iSeg + "_" + cSeg + scopeSuffix + ".json"
			}
		}
		baseDir := filepath.Join(homeDir, ".cloud_idaas", "human-cache")
		finalPath := filepath.Join(baseDir, fileName)
		// 纵深防御:即便 sanitizeCacheSegment 出了回归,join+Clean 后的结果仍必须在
		// baseDir 之内;否则退化到 baseDir 下的固定文件名,宁可缓存串用也不穿越目录。
		if !strings.HasPrefix(filepath.Clean(finalPath)+string(filepath.Separator), filepath.Clean(baseDir)+string(filepath.Separator)) &&
			filepath.Clean(finalPath) != filepath.Clean(baseDir) {
			finalPath = filepath.Join(baseDir, "fallback_cache.json")
		}
		provider.localHumanCachePath = finalPath
	}

	// 构造函数不再触发 IO/Device Code 流程。
	// 原 provider.getCredential() 会阻塞最长 180 秒等待用户扫码，导致：
	// 1) factory 单例 Init 时若网络异常或用户离开会 hang
	// 2) 返回值被丢弃，初始化失败无法察觉
	// 首次调用 GetCredential()/GetOidcToken() 时由 refresh 的首次启动分支触发。

	return provider
}

// GetOidcToken 获取 OIDC Token。内部委托给 GetCredentialWithContext,使用 context.Background()。
func (p *HumanFederatedOidcTokenProvider) GetOidcToken() (string, error) {
	result, err := p.GetCredentialWithContext(context.Background())
	if err != nil {
		return "", err
	}
	return result.GetAccessToken(), nil
}

// GetCredential 实现 IDaaSCredentialProvider 接口。内部委托给 GetCredentialWithContext。
func (p *HumanFederatedOidcTokenProvider) GetCredential() (credential.IDaaSCredential, error) {
	return p.GetCredentialWithContext(context.Background())
}

// GetCredentialWithContext 获取凭证,带 context。ctx 透传到 token endpoint 请求和
// device code 轮询,使调用方可取消长时间等待的 device authorization 流程。
func (p *HumanFederatedOidcTokenProvider) GetCredentialWithContext(ctx context.Context) (credential.IDaaSCredential, error) {
	result, err := p.getCredential(ctx)
	if err != nil {
		return nil, err
	}
	return &result.Value, nil
}

// getCredential 获取凭证，缓存与刷新时机交给 supplier。
func (p *HumanFederatedOidcTokenProvider) getCredential(ctx context.Context) (*cache.RefreshResult[credential.IDaaSTokenResponse], error) {
	return p.getSupplier().GetWithContext(ctx)
}

func (p *HumanFederatedOidcTokenProvider) getSupplier() *cache.CachedResultSupplier[credential.IDaaSTokenResponse] {
	// double-checked locking。热路径先 RLock 快照，已初始化则直接返回，
	// 避免每次取凭证都串行化。仅首次（supplier==nil）回退到写锁内初始化。
	p.supplierMu.RLock()
	s := p.supplier
	p.supplierMu.RUnlock()
	if s != nil {
		return s
	}
	p.supplierMu.Lock()
	defer p.supplierMu.Unlock()
	if p.supplier == nil {
		behavior := p.staleBehavior
		if behavior == "" {
			behavior = enums.StaleValueBehaviorRefresh
		}
		p.supplier = cache.NewCachedResultSupplier(p.refresh, behavior)
		// 设置 scope 使 RefreshEvent 能携带 scope 信息。
		p.supplier.WithScope(p.scope)
		// 注入 factory baseCtx:device flow 后台刷新 worker
		// 据此感知宿主关闭。nil(直接构造/测试)时 supplier 内部回退 Background。
		if p.baseCtx != nil {
			p.supplier.WithBaseContext(p.baseCtx)
		}
		// device flow 最长 180s(MaxWaitIntervalSeconds)等待用户扫码,
		// 默认 asyncRefreshTimeout=120s 会截断合法流程,设为 190s 覆盖完整等待窗口。
		p.supplier.WithAsyncRefreshTimeout(time.Duration(MaxWaitIntervalSeconds)*time.Second + 10*time.Second)
	}
	return p.supplier
}

// Close 释放 supplier 持有的后台资源。
//
// Human provider 不复用 AbstractRefreshedCredentialProvider(它直接持有 supplier),
// 因此单独实现 Close:provider 不再被使用时(如 factory Reset)释放注入的
// PrefetchStrategy / 后台 goroutine,避免孤儿 goroutine 泄漏。
// supplier 尚未懒初始化(从未获取过凭证)时为 no-op。多次调用安全。
//
// 在 supplierMu 锁内读取并置空 supplier，与 getSupplier 的读写建立
// happens-before，消除原 bare read 的 data race。CachedResultSupplier.Close
// 自身幂等，即便 getSupplier 并发拿到旧引用也只是对一个已 Close 的 supplier
// 多调一次 Close（no-op）。
func (p *HumanFederatedOidcTokenProvider) Close() error {
	p.supplierMu.Lock()
	s := p.supplier
	p.supplier = nil
	p.supplierMu.Unlock()
	if s != nil {
		return s.Close()
	}
	return nil
}

// refresh 是 supplier 的 refreshFunc (ctx 透传)：
// 首次启动时复用本地缓存，没有可用缓存再走 device flow；之后用上一次的 refresh_token 刷新。
func (p *HumanFederatedOidcTokenProvider) refresh(ctx context.Context) (*cache.RefreshResult[credential.IDaaSTokenResponse], error) {
	p.tokenMu.Lock()
	last := p.lastToken
	p.tokenMu.Unlock()

	var token *credential.IDaaSTokenResponse
	if last == nil {
		var cacheErr error
		token, cacheErr = p.tryReuseLocalCache(ctx)
		if token == nil {
			// cache-reuse 分支错误处理策略与 lastToken 分支一致:
			// - invalid_grant(token 确认失效) → 回退到 device flow;
			// - 瞬时错误(网络/5xx/cancel) → 向上抛出,不回退到 device flow,
			// 避免每次瞬时故障都强迫用户重新扫码。
			if cacheErr != nil && !isInvalidGrantError(cacheErr) {
				return nil, cacheErr
			}
			if cacheErr != nil {
				logger.Default().Warn(ctx, "cached refresh token invalid, falling back to device flow",
					"event", "human.fallback_device_flow", "error", cacheErr.Error())
			}
			var err error
			token, err = p.getTokenWithDeviceAuthorization(ctx)
			if err != nil {
				return nil, err
			}
			logger.Default().Info(ctx, "token authn time",
				"event", "human.token_authn", "timestamp", cache.GetClock().Now().UnixMilli())
			p.writeToLocalCache(token)
		}
	} else {
		refreshToken := last.GetRefreshToken()
		var err error
		if refreshToken != "" {
			token, err = p.refreshToken(ctx, refreshToken)
		}
		// 若服务端在 refresh 响应中省略了 refresh_token(新 token 的
		// RefreshToken 为空),保留/复用旧 token 的 refresh_token,避免下次刷新
		// 因 refresh_token 为空而回退到 device flow,迫使用户重新授权。
		if token != nil && token.RefreshToken == "" {
			token.RefreshToken = last.RefreshToken
		}
		if token == nil {
			// refresh_token 缺失或刷新失败时的回退策略:
			// - 仅当 refresh_token 确认失效 (invalid_grant) 才回退到 device flow,
			// 重新引导用户授权——这是拿到新 human token 的唯一途径;
			// - 网络抖动等瞬时错误不回退,直接向上抛出,避免每次瞬时故障都强迫用户重新扫码。
			if err != nil && !isInvalidGrantError(err) {
				return nil, err
			}
			if err != nil {
				logger.Default().Warn(ctx, "refresh token invalid, falling back to device flow",
					"event", "human.fallback_device_flow", "error", err.Error())
			}
			token, err = p.getTokenWithDeviceAuthorization(ctx)
			if err != nil {
				return nil, err
			}
		}
		logger.Default().Info(ctx, "token refresh time",
			"event", "human.token_refresh", "timestamp", cache.GetClock().Now().UnixMilli())
		// 每次刷新都写入本地缓存
		p.writeToLocalCache(token)
	}

	p.tokenMu.Lock()
	p.lastToken = token
	p.tokenMu.Unlock()

	// 传入 token 的真实 ReceivedAt 而非零值,使 NewRefreshResult 计算
	// ExpiresAt = ReceivedAt + ExpiresIn(真实剩余生命周期)。零值会使 NewRefreshResult
	// 回退到 GetClock().Now(),对磁盘缓存复用的 token 会得到完整 TTL from now,
	// 将 30 分钟前收到、TTL 1h 的 token 当作从现在起 1h 有效。
	// 对于网络获取的 token,ReceivedAt 由 UnmarshalJSON 设为 time.Now(),与
	// GetClock().Now() 在生产环境等价;磁盘缓存的 ReceivedAt 由 MarshalJSON/
	// UnmarshalJSON 从 received_at 字段恢复为原始接收时间。
	result, err := cache.NewRefreshResult(*token, token.ReceivedAt, token.ExpiresIn)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// tryReuseLocalCache 尝试复用本地缓存 (ctx 透传)。
// 返回 (nil, nil) 表示没有可用缓存(文件不存在/解析失败/access_token 为空/无 refresh_token);
// 返回 (token, nil) 表示成功复用缓存或刷新成功;
// 返回 (nil, err) 表示缓存刷新遇到瞬时错误(网络/5xx/cancel),调用方应传播而非回退 device flow。
// invalid_grant 错误返回 (nil, nil),表示 token 确认失效,调用方可回退 device flow。
func (p *HumanFederatedOidcTokenProvider) tryReuseLocalCache(ctx context.Context) (*credential.IDaaSTokenResponse, error) {
	data, err := util.ReadFile(p.localHumanCachePath)
	if err != nil {
		logger.Default().Debug(ctx, "read local cache failed",
			"event", "human.cache_read", "error", err.Error())
		return nil, nil
	}

	var localToken credential.IDaaSTokenResponse
	if err := json.Unmarshal(data, &localToken); err != nil {
		logger.Default().Debug(ctx, "parse local cache failed",
			"event", "human.cache_parse", "error", err.Error())
		return nil, nil
	}

	if localToken.GetAccessToken() == "" {
		return nil, nil
	}

	// 缺少 received_at 字段的缓存文件(旧版本写入),UnmarshalJSON 会将其设为 time.Now(),
	// 使一个 30 分钟前收到、TTL 1h 的过期 token 被当作"刚收到、还有 1h 有效"。
	// 检测原始 JSON 是否含 received_at:缺失则将 ReceivedAt 清零,WillSoonExpire 会
	// 判定 token 已过期(expiryTime = epoch + TTL,远早于 thresholdTime),强制刷新。
	if !bytes.Contains(data, []byte(`"received_at"`)) {
		localToken.ReceivedAt = time.Time{}
	}

	// 检查是否即将过期（提前 1/3 过期时间认为即将过期）
	thresholdSeconds := localToken.ExpiresIn / 3
	if !localToken.WillSoonExpire(thresholdSeconds) {
		return &localToken, nil
	}

	refreshToken := localToken.GetRefreshToken()
	if refreshToken == "" {
		return nil, nil
	}

	tokenResponse, err := p.refreshToken(ctx, refreshToken)
	if err != nil {
		// 区分 invalid_grant 与瞬时错误,与 lastToken 分支策略一致:
		// - invalid_grant: token 确认失效,返回 (nil, nil) 让调用方回退 device flow;
		// - 瞬时错误(网络/5xx/cancel): 返回 (nil, err) 让调用方传播,不回退 device flow。
		if isInvalidGrantError(err) {
			logger.Default().Debug(ctx, "cached refresh token invalid (invalid_grant)",
				"event", "human.cache_refresh", "error", err.Error())
			return nil, nil
		}
		logger.Default().Warn(ctx, "refresh token failed in cache reuse (transient)",
			"event", "human.cache_refresh", "error", err.Error())
		return nil, err
	}

	// 若服务端在 refresh 响应中省略了 refresh_token(新 token 的
	// RefreshToken 为空),保留/复用磁盘缓存中的旧 refresh_token,避免下次刷新
	// 因 refresh_token 为空而回退到 device flow。
	if tokenResponse.RefreshToken == "" {
		tokenResponse.RefreshToken = localToken.RefreshToken
	}

	logger.Default().Info(ctx, "token refresh time",
		"event", "human.token_refresh", "timestamp", cache.GetClock().Now().UnixMilli())

	p.writeToLocalCache(tokenResponse)
	return tokenResponse, nil
}

// getTokenWithDeviceAuthorization 通过 Device Code 流程获取令牌 (ctx 透传)
func (p *HumanFederatedOidcTokenProvider) getTokenWithDeviceAuthorization(ctx context.Context) (*credential.IDaaSTokenResponse, error) {
	deviceCodeResponse, err := p.oauth2Util.GetDeviceCodeWithContext(
		ctx,
		p.deviceAuthorizationEndpoint,
		p.clientId,
		p.scope,
	)
	if err != nil {
		return nil, err
	}

	// user_code 与 verification URL 走宿主 handler,
	// 不进结构化日志。user_code 是 RFC 8628 一次性展示码(短生命周期、设计上
	// 人类可见),非长生命周期凭证;但它一旦进入持久化集中式日志,可被他人抢在
	// 合法用户前完成 device 授权。故 SDK 仅记录"已收到 device code、请在浏览器/
	// 终端完成"的非 code 消息,把 URI/code 本体交给 handler(默认 stdout 打印,
	// 服务端集成注入 handler 覆盖)。
	//
	// verification_uri_complete 优先(内嵌 user_code 免手输);缺失时退化到
	// bare verification_uri + user_code(用户手输)。两种情况都把 user_code 透传给
	// handler,handler 决定是否打印/渲染/打开浏览器(库边界 side-effect 由宿主决定,
	// SDK 自身不主动调 OpenBrowser —— 与原实现相比,这里删掉了 SDK 的 OpenBrowser 调用,
	// 把"是否打开浏览器"的责任交给 handler)。
	uri := deviceCodeResponse.VerificationURIComplete
	if uri == "" {
		uri = deviceCodeResponse.VerificationURI
	}
	logger.Default().Info(ctx, "device authorization code received, awaiting user completion",
		"event", "human.device_code")
	// 不 recover handler(:宿主回调 panic 属宿主责任,库边界不吞);
	// handler 默认 util.PrintUserCode(CLI),nil 仅出现在测试/未初始化路径 ——
	// 此时退化为 PrintUserCode 保证用户仍能看到 code。
	if p.userCodeHandler != nil {
		p.userCodeHandler(uri, deviceCodeResponse.UserCode)
	} else {
		util.PrintUserCode(uri, deviceCodeResponse.UserCode)
	}

	// 轮询获取令牌。优先尊重服务端返回的 expires_at / expires_in，缺失时再使用默认等待上限。
	pollInterval := deviceCodeResponse.Interval
	if pollInterval <= 0 {
		pollInterval = DefaultPollInterval
	}
	// ID014: 施加上界,IdP 异常返回超大 interval 不污染轮询节奏。
	if pollInterval > MaxPollInterval {
		pollInterval = MaxPollInterval
	}
	deadline := resolveDeviceCodeDeadline(deviceCodeResponse.ExpiresAt, deviceCodeResponse.ExpiresIn)

	for cache.GetClock().Now().Before(deadline) {
		sleepDuration := time.Duration(pollInterval) * time.Second
		// 用注入时钟计算剩余时间,与循环条件 cache.GetClock().Now() 同源,
		// 避免 MockClock 注入时两者读数不一致导致 sleepDuration 计算错误(time.Until 会用真实时钟)。
		if remaining := deadline.Sub(cache.GetClock().Now()); remaining < sleepDuration {
			sleepDuration = remaining
		}
		if sleepDuration <= 0 {
			break
		}
		// 用 NewTimer + 显式 Stop 替代 time.After。
		// time.After 在 select 选中 ctx.Done() 分支时会泄漏 timer 直到 sleepDuration
		// 到期才被 GC(device code 轮询每轮最长 5s,用户取消后该 timer 仍占底层计时器
		// 槽位至到期);NewTimer + Stop 在 ctx.Done() 分支立即释放,避免长轮询取消
		// 时累积泄漏的 timer。Stop 返回 false 表示 timer 已 fire(C 已有数据),
		// 此处无需 Drain —— 选中 ctx.Done() 即 return,C 无人读,GC 回收即可。
		timer := time.NewTimer(sleepDuration)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		}

		token, err := p.oauth2Util.GetTokenByDeviceCodeWithContext(
			ctx,
			p.tokenEndpoint,
			p.clientId,
			deviceCodeResponse.DeviceCode,
		)
		if err != nil {
			// 优先识别 OAuth2 标准 error code（RFC 8628）：
			// authorization_pending → 用户尚未完成授权，继续 poll
			// slow_down → 服务端要求降低 poll 频率，应增加 interval
			// access_denied → 用户拒绝授权，立即终止
			// expired_token → device_code 已过期，立即终止
			// 其它 OAuth2 错误 → 立即抛出
			var oauth2Err *sdkerrors.OAuth2Error
			if errors.As(err, &oauth2Err) {
				switch oauth2Err.OAuthCode {
				case "authorization_pending":
					continue
				case "slow_down":
					pollInterval += 5
					// ID014: 多次 slow_down 累加上界,避免无限增长。
					if pollInterval > MaxPollInterval {
						pollInterval = MaxPollInterval
					}
					continue
				case "access_denied", "expired_token":
					return nil, sdkerrors.NewClientError(
						oauth2Err.OAuthCode,
						"device authorization terminated: "+oauth2Err.OAuthCode+": "+oauth2Err.OAuthDescription,
						err,
					)
				default:
					return nil, err
				}
			}
			// 任意 HTTP 400 不视为 authorization_pending 继续轮询,否则会
			// 掩盖 invalid_client/invalid_request 等应当立即终止的错误(非标 body
			// 无法解析出 OAuth2Error,走到这里时已确认不是标准 OAuth2 响应)。
			// 仅当 400 响应体明确含 "pending" 时才继续轮询(兼容非标 pending 响应);
			// 否则返回错误让调用方感知真实失败原因。
			var httpErr *sdkerrors.HttpError
			if errors.As(err, &httpErr) && httpErr.StatusCode == 400 &&
				strings.Contains(strings.ToLower(httpErr.ErrorMessage()), "pending") {
				continue
			}
			return nil, err
		}

		if token != nil && token.GetAccessToken() != "" {
			return token, nil
		}
	}

	return nil, sdkerrors.NewClientError(constants.DeviceCodeTimeout, "waiting for token timeout", nil)
}

// resolveDeviceCodeDeadline 计算 device flow 轮询截止时间。
//
// 优先级：服务端绝对过期时间 expires_at > 相对过期时间 expires_in > 默认上限。
// expires_at 必须晚于当前时间才采用，否则（时钟漂移 / 服务端异常返回过去的时间戳）
// 直接使用会导致一次轮询都不进入就立即超时，因此回退到 expires_in 或默认上限。
//
// expires_in 是 IdP 可控的 int64,直接做 time.Duration(expiresIn)*time.Second
// 在超大值(>~3.17e9 秒)时会溢出回绕为负值,使 deadline 落到过去 → 一次轮询都不进入。
// 这里用 util.DurationFromSeconds 钳位换算,并对 expires_in / expires_at 两条路径
// 都施加 MaxWaitIntervalSeconds 上限:device flow 是交互式流程,等待超过 180s 无意义,
// 服务端即便返回超长过期时间也不应让用户空等。
func resolveDeviceCodeDeadline(expiresAt, expiresIn int64) time.Time {
	now := cache.GetClock().Now()
	maxDeadline := now.Add(MaxWaitIntervalSeconds * time.Second)
	if expiresAt > 0 {
		deadline := time.Unix(expiresAt, 0)
		if deadline.After(now) {
			if deadline.After(maxDeadline) {
				return maxDeadline
			}
			return deadline
		}
	}
	if expiresIn > 0 {
		deadline := now.Add(util.DurationFromSeconds(expiresIn))
		if deadline.After(maxDeadline) {
			return maxDeadline
		}
		return deadline
	}
	return maxDeadline
}

// isInvalidGrantError 判断错误是否表示 refresh_token 已失效。
//
// OAuth2 token endpoint在 refresh_token 过期 / 被撤销时返回 error="invalid_grant"
// (RFC 6749)。这类错误意味着继续重试 refresh 不会成功,应回退到 device flow
// 让用户重新授权;而网络抖动 / 5xx 等瞬时错误不应触发回退,避免强迫用户重新扫码。
func isInvalidGrantError(err error) bool {
	var oauth2Err *sdkerrors.OAuth2Error
	if errors.As(err, &oauth2Err) {
		return oauth2Err.OAuthCode == "invalid_grant"
	}
	return false
}

// refreshToken 通过 refresh_token 刷新令牌 (ctx 透传)
func (p *HumanFederatedOidcTokenProvider) refreshToken(ctx context.Context, refreshToken string) (*credential.IDaaSTokenResponse, error) {
	return p.oauth2Util.RefreshTokenWithContext(
		ctx,
		p.tokenEndpoint,
		p.clientId,
		refreshToken,
	)
}

// writeToLocalCache 写入本地缓存
func (p *HumanFederatedOidcTokenProvider) writeToLocalCache(token *credential.IDaaSTokenResponse) {
	data, err := json.Marshal(token)
	if err != nil {
		logger.Default().Warn(context.Background(), "marshal token failed",
			"event", "human.cache_write", "error", err.Error())
		return
	}

	// 确保目录存在；使用 0700（drwx------），仅当前用户可访问，
	// 防止同机器其他账号通过 ls 枚举或读取目录下的 token 文件。
	cacheDir := filepath.Dir(p.localHumanCachePath)
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		logger.Default().Warn(context.Background(), "create cache directory failed",
			"event", "human.cache_write", "error", err.Error())
		return
	}

	if err := util.WriteFile(p.localHumanCachePath, data); err != nil {
		logger.Default().Warn(context.Background(), "write local cache failed",
			"event", "human.cache_write", "error", err.Error())
	}
}

// GetClientId 获取 Client ID
func (p *HumanFederatedOidcTokenProvider) GetClientId() string {
	return p.clientId
}

// GetTokenEndpoint 获取 Token Endpoint
func (p *HumanFederatedOidcTokenProvider) GetTokenEndpoint() string {
	return p.tokenEndpoint
}

// GetDeviceAuthorizationEndpoint 获取 Device Authorization Endpoint
func (p *HumanFederatedOidcTokenProvider) GetDeviceAuthorizationEndpoint() string {
	return p.deviceAuthorizationEndpoint
}
