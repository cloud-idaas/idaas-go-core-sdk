package authentication

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cloud-idaas/idaas-go-core-sdk/constants"
	"github.com/cloud-idaas/idaas-go-core-sdk/domain"
	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
	"github.com/cloud-idaas/idaas-go-core-sdk/errors"
	"github.com/cloud-idaas/idaas-go-core-sdk/http"
	"github.com/cloud-idaas/idaas-go-core-sdk/logger"
	"github.com/cloud-idaas/idaas-go-core-sdk/util"
)

// AzureVmOidcTokenProvider Azure VM Managed Identity OIDC Token 提供者。
// 通过 Azure IMDS 获取 Managed Identity ID Token，用于 IDaaS OIDC 联邦认证：
//
//	GET http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com%2F
//	Header: Metadata: true
//
// 适用场景：authnMethod=OIDC、clientDeployEnvironment=AZURE_VM。
// resource 固定 https://management.azure.com/（取 ARM 令牌）；IMDS 返回 JSON
// {"access_token":"<JWT>","expires_on":"<unix秒>",...}；用 expires_on 判过期、过期前 10 分钟
// 主动刷新，expires_on 解析失败回退到 JWT payload 的 exp，都失败则禁用缓存。
// 参考：https://learn.microsoft.com/azure/active-directory/managed-identities-azure-resources/how-to-use-vm-token
//
// 并发模型(复用模式):singleflight 保证同一时刻至多 1 个 IMDS
// 在飞请求/supplier。leader(cache-miss/expired)spawn detached
// worker runAzureFetch;waiter(已有在飞)等 inf.done 或 caller ctx 取消。worker
// 顶层 recover 写非 nil err + 强制 closeDone;scoped lock 写缓存临界区
// panic 也释放 mu;IMDS 操作 ctx = WithTimeout(baseCtx, imdsTimeout)。
// worker 内日志 ctx 用 logger.WithoutCancel(baseCtx),不得用
// context.Background() 也不得用会被取消的 refresh ctx。
type AzureVmOidcTokenProvider struct {
	httpClient http.HttpClient

	mu          sync.Mutex
	cachedToken string
	expiresAt   int64 // unix 秒
	// inflight 当前在飞的 IMDS 刷新;nil = 无在飞。mu 保护。singleflight 语义:
	// 同一时刻至多 1 个非 nil inflight,leader 唯一 spawn 点,waiter 不 spawn。
	inflight *azureInflight
	// baseCtx factory 注入的宿主级 ctx(与 CachedResultSupplier 同源)。
	// nil 仅限非 factory 直接构造(测试)路径,runAzureFetch 内回退 Background。
	// 生产路径(factory) 始终非 nil →"goroutine 可被宿主关闭"默认满足。
	baseCtx context.Context
	// imdsTimeout IMDS 请求超时;0 = 用 DefaultAzureImdsTimeout。
	imdsTimeout time.Duration
}

// azureImdsTokenResponse Azure IMDS Managed Identity Token 接口返回体
//
// 字段含义参考 https://learn.microsoft.com/azure/active-directory/managed-identities-azure-resources/how-to-use-vm-token#get-a-token-using-http
// 注意 expires_on / expires_in 等数值字段在 IMDS 响应中均为字符串类型（Azure 的历史设计）
type azureImdsTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresOn   string `json:"expires_on"`
	ExpiresIn   string `json:"expires_in"`
	TokenType   string `json:"token_type"`
	Resource    string `json:"resource"`
}

// azureInflight 单次在飞 IMDS 刷新的同步槽(同 inflightCall 模式)。
// done 由 sync.Once close 幂等;token/err/expiresAt 由 worker 写,
// waiter 经 <-done 读到一致结果,绝不拿 (nil,"")。
type azureInflight struct {
	done      chan struct{}
	once      sync.Once
	token     string
	expiresAt int64
	err       error
}

// newAzureInflight 构造一个未完成的在飞槽。
func newAzureInflight() *azureInflight {
	return &azureInflight{done: make(chan struct{})}
}

// closeDone 幂等关闭 done(sync.Once)。worker 正常完成与 recover 兜底
// 都调它,双关安全。
func (a *azureInflight) closeDone() {
	a.once.Do(func() { close(a.done) })
}

// NewAzureVmOidcTokenProvider 创建 AzureVmOidcTokenProvider
//
// httpClient：HTTP 客户端（必填）
func NewAzureVmOidcTokenProvider(httpClient http.HttpClient) *AzureVmOidcTokenProvider {
	return &AzureVmOidcTokenProvider{
		httpClient: httpClient,
	}
}

// WithBaseContext 注入宿主级 baseCtx(factory 路径,与 CachedResultSupplier
// 同源)。baseCtx 取消时,在飞 worker 的 refreshCtx(WithTimeout(baseCtx,...))
// 收 ctx.Done 提前返回,worker 不挂到 imdsTimeout("goroutine 可被宿主关闭")。
//
// Experimental: GA 前可能调整 baseCtx 注入方式。
func (p *AzureVmOidcTokenProvider) WithBaseContext(ctx context.Context) *AzureVmOidcTokenProvider {
	p.baseCtx = ctx
	return p
}

// WithImdsTimeout 覆盖 IMDS 请求超时(默认 DefaultAzureImdsTimeout)。
// 仅供宿主在慢实例/特殊网络下调;生产路径无须调用。
//
// Experimental: GA 前可能调整。
func (p *AzureVmOidcTokenProvider) WithImdsTimeout(d time.Duration) *AzureVmOidcTokenProvider {
	p.imdsTimeout = d
	return p
}

// GetOidcToken 获取 OIDC Token（带轻量缓存，过期前 10 分钟刷新）
func (p *AzureVmOidcTokenProvider) GetOidcToken() (string, error) {
	return p.GetOidcTokenWithContext(context.Background())
}

// GetOidcTokenWithContext 获取 OIDC Token,带 context。
// ctx 透传到 waiter 的 select 与 IMDS 请求(worker 内 WithTimeout(baseCtx,...)),
// 使调用方可取消长时间挂起的元数据调用。
//
// leader/waiter 分离:
//   - leader(cachedToken 空/willSoonExpire 且无在飞):占 inflight 槽,spawn
//     runAzureFetch worker,自己走 waitAzureInflight 等 worker。
//   - waiter(已有 inflight):不 spawn,直接 waitAzureInflight 复用 leader 的结果
//     (singleflight:并发 N 调用仅 1 次 IMDS hit)。
func (p *AzureVmOidcTokenProvider) GetOidcTokenWithContext(ctx context.Context) (string, error) {
	p.mu.Lock()
	if p.cachedToken != "" && !p.willSoonExpire() {
		token := p.cachedToken
		p.mu.Unlock()
		return token, nil
	}
	// waiter:已有在飞刷新 → 等它,不 spawn(singleflight)。
	if p.inflight != nil {
		inf := p.inflight
		p.mu.Unlock()
		return p.waitAzureInflight(ctx, inf)
	}
	// leader:占在飞槽,快照 baseCtx/timeout 后释放锁再 spawn worker。
	inf := newAzureInflight()
	p.inflight = inf
	baseCtx := p.baseCtx
	timeout := p.imdsTimeout
	if timeout <= 0 {
		timeout = constants.DefaultAzureImdsTimeout
	}
	p.mu.Unlock()

	go p.runAzureFetch(timeout, inf, baseCtx)
	return p.waitAzureInflight(ctx, inf)
}

// waitAzureInflight 等待在飞刷新完成,响应 caller ctx 取消(同 plain select,
// 非 waitInflight:Azure 无 stale 旧值 fallback 语义,cache-miss/expired 无可返旧值)。
// worker 取消后 waiter 拿不到结果(ctx.Done 先就绪),由调用方重试;worker 仍 detached
// 完成,结果由 runAzureFetch 提交缓存供后续调用。
func (p *AzureVmOidcTokenProvider) waitAzureInflight(ctx context.Context, inf *azureInflight) (string, error) {
	select {
	case <-inf.done:
		return inf.token, inf.err
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// runAzureFetch detached worker 体(复用 runRefreshAndCommit 模式)。
//
// 顶层 recover:任何 panic(IMDS 请求/JSON 解析/锁操作)都写非 nil CredentialError
// (AzureVmIdentityTokenFetchFailed,凭证类,recovered 转 string 入 message
// 不入 kv,cause=nil) 并强制 closeDone,不让 waiter 拿 ("","") 也不让 panic
// 击穿宿主。scoped lock 写缓存临界区 panic 也释放 mu;closeDone 由
// sync.Once 幂等,正常路径与 recover 兜底双调安全。
//
// IMDS 操作 ctx = WithTimeout(baseCtx, timeout):可被 baseCtx(宿主)取消,不绑定
// 任一调用方 ctx(worker 是共享刷新)。baseCtx nil → Background 兜底(零回归,
// 非 factory 直接构造路径)。worker 内日志 ctx 用 logger.WithoutCancel(baseCtx):
// refresh ctx 可能已被取消,日志仍须落盘,不得用 context.Background()
// 也不得用会被取消的 refresh ctx。
func (p *AzureVmOidcTokenProvider) runAzureFetch(
	timeout time.Duration,
	inf *azureInflight,
	baseCtx context.Context,
) {
	func() {
		defer func() {
			if r := recover(); r != nil {
				inf.err = errors.NewCredentialError(
					constants.AzureVmIdentityTokenFetchFailed,
					fmt.Sprintf("azure IMDS fetch panicked; recovered: %v", r),
					nil,
				)
				inf.token = ""
				// 日志 ctx 用 WithoutCancel(baseCtx):refresh ctx 可能已被取消,
				// 日志仍须落盘,不得用 Background 也不得用会被取消的 refresh ctx。
				logCtx := logger.WithoutCancel(p.effectiveBaseContext(baseCtx))
				logger.Default().Error(logCtx,
					"azure IMDS fetch panic recovered",
					"event", "azure.imds", "status", "panic", "error", fmt.Sprint(r))
			}
			// scoped lock:写缓存 + 清在飞槽。临界区 panic 也释放 mu(scoped defer Unlock)。
			// singleflight 严格语义下同一时刻仅 1 inflight,worker 完成时不会被 supersede,
			// cachedToken 无条件写安全;`if p.inflight==inf` 守卫仅防 Reset/竞态极端(防御性)。
			func() {
				defer func() { _ = recover() }()
				p.mu.Lock()
				defer p.mu.Unlock()
				if inf.err == nil && inf.token != "" {
					p.cachedToken = inf.token
					p.expiresAt = inf.expiresAt
				}
				if p.inflight == inf {
					p.inflight = nil
				}
			}()
			// 终极兜底 closeDone:正常路径下方 fetchImds 成功后已写 inf.token/err,
			// 此处 close 释放 waiter;panic 路径下上面已写 inf.err,此处 close 同样释放。
			inf.closeDone()
		}()

		if baseCtx == nil {
			baseCtx = context.Background() // 零回归:非 factory 直接构造(测试)路径
		}
		refreshCtx, cancel := context.WithTimeout(baseCtx, timeout)
		defer cancel()
		token, expiresAt, ferr := p.fetchImds(refreshCtx)
		inf.token = token
		inf.expiresAt = expiresAt
		inf.err = ferr
	}()
}

// fetchImds 执行一次 IMDS token 请求 + 解析,返回 (token, expiresAt unix秒, err)。
// 不触碰 p.mu(无锁副作用),由调用方(worker)在 scoped lock 内写缓存。
func (p *AzureVmOidcTokenProvider) fetchImds(ctx context.Context) (tok string, expiresAt int64, err error) {
	tokenUrl := fmt.Sprintf(constants.AzureVmIdentityTokenUrlTemplate, url.QueryEscape(constants.AzureVmManagementResource))
	resp, err := p.httpClient.ExecuteContext(ctx, &domain.HttpRequest{
		Method: enums.HttpMethodGet,
		URL:    tokenUrl,
		Headers: map[string]string{
			constants.HeaderMetadata: constants.HeaderMetadataValueTrue,
		},
	})
	if err != nil {
		return "", 0, errors.NewCredentialError(
			constants.AzureVmIdentityTokenFetchFailed,
			fmt.Sprintf("Failed to fetch Azure VM identity token: %s", err.Error()),
			err,
		)
	}
	if !resp.IsSuccess() {
		return "", 0, errors.NewHttpError(
			constants.ClientError,
			fmt.Sprintf("Failed to fetch Azure VM identity token (HTTP %d): %s", resp.StatusCode, util.TruncateForError(resp.Body, 512)),
			resp.StatusCode,
			nil,
		)
	}

	var imdsResp azureImdsTokenResponse
	if err := json.Unmarshal(resp.Body, &imdsResp); err != nil {
		return "", 0, errors.NewCredentialError(
			constants.AzureVmIdentityTokenInvalidJson,
			fmt.Sprintf("Failed to parse Azure VM identity token JSON: %s", err.Error()),
			err,
		)
	}

	token := strings.TrimSpace(imdsResp.AccessToken)
	if token == "" {
		return "", 0, errors.NewCredentialError(
			constants.AzureVmIdentityTokenEmpty,
			"Azure VM identity token response missing access_token field",
			nil,
		)
	}

	return token, resolveAzureTokenExpiresAt(imdsResp.ExpiresOn, token), nil
}

// effectiveBaseContext 在 baseCtx 入参非 nil 时直接用,否则锁内再读一次字段
// (recover 路径下 runAzureFetch 入参可能已 fallback Background,但日志希望拿原始
// baseCtx 透传 trace 关联)。同 effectiveBaseContext。
func (p *AzureVmOidcTokenProvider) effectiveBaseContext(baseCtx context.Context) context.Context {
	if baseCtx != nil {
		return baseCtx
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.baseCtx
}

// willSoonExpire 判断 token 是否即将在缓冲时间内过期
func (p *AzureVmOidcTokenProvider) willSoonExpire() bool {
	if p.expiresAt <= 0 {
		return true
	}
	now := time.Now().Unix()
	return (p.expiresAt - now) < constants.TokenRefreshBufferSeconds
}

// resolveAzureTokenExpiresAt 解析 token 过期时间（unix 秒）
//
// 优先级：
// 1. IMDS 响应里的 expires_on（unix 秒字符串，Azure 官方推荐字段）
// 2. JWT payload 里的 exp 字段（兜底）
// 3. 都解析不出来 -> 返回 0，表示不缓存
func resolveAzureTokenExpiresAt(expiresOnStr, jwtToken string) int64 {
	if expiresOnStr != "" {
		if exp, err := strconv.ParseInt(expiresOnStr, 10, 64); err == nil && exp > 0 {
			return exp
		}
	}
	if exp, err := parseJwtExpiration(jwtToken); err == nil {
		return exp
	}
	return 0
}
