package authentication

import (
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cloud-idaas/idaas-go-core-sdk/cache"
	"github.com/cloud-idaas/idaas-go-core-sdk/constants"
	"github.com/cloud-idaas/idaas-go-core-sdk/credential"
	sdkerrors "github.com/cloud-idaas/idaas-go-core-sdk/errors"
	"github.com/cloud-idaas/idaas-go-core-sdk/http"
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
)

// HumanFederatedOidcTokenProvider 人类联邦 OIDC Token 提供者 (§5.6 HUMAN)
// 支持 Device Code 流程和本地缓存复用
type HumanFederatedOidcTokenProvider struct {
	clientId                    string
	scope                       string
	tokenEndpoint               string
	deviceAuthorizationEndpoint string
	localHumanCachePath         string
	httpClient                  http.HttpClient
	oauth2Util                  *oauth2.OAuth2TokenUtil

	mu           sync.Mutex
	cachedResult *cache.RefreshResult[credential.IDaaSTokenResponse]
	firstStartup bool
}

// NewHumanFederatedOidcTokenProvider 创建 HumanFederatedOidcTokenProvider
func NewHumanFederatedOidcTokenProvider(
	clientId string,
	tokenEndpoint string,
	deviceAuthorizationEndpoint string,
	httpClient http.HttpClient,
) *HumanFederatedOidcTokenProvider {
	provider := &HumanFederatedOidcTokenProvider{
		clientId:                    clientId,
		scope:                       DefaultScope,
		tokenEndpoint:               tokenEndpoint,
		deviceAuthorizationEndpoint: deviceAuthorizationEndpoint,
		httpClient:                  httpClient,
		oauth2Util:                  oauth2.NewOAuth2TokenUtil(httpClient),
		firstStartup:                true,
	}

	// 设置本地缓存路径
	envPath := os.Getenv(constants.EnvHumanCredentialCachePathKey)
	if envPath != "" {
		provider.localHumanCachePath = envPath
	} else {
		// 默认路径：~/.cloud_idaas/human-cache/{clientId}.json
		homeDir, err := os.UserHomeDir()
		if err != nil {
			homeDir = "."
		}
		provider.localHumanCachePath = filepath.Join(homeDir, ".cloud_idaas", "human-cache", clientId+".json")
	}

	// 构造函数不再触发 IO/Device Code 流程。
	// 原 provider.getCredential() 会阻塞最长 180 秒等待用户扫码，导致：
	//   1) factory 单例 Init 时若网络异常或用户离开会 hang
	//   2) 返回值被丢弃，初始化失败无法察觉
	// 首次调用 GetCredential()/GetOidcToken() 时会通过 firstStartup 分支自动触发。

	return provider
}

// GetOidcToken 获取 OIDC Token
func (p *HumanFederatedOidcTokenProvider) GetOidcToken() (string, error) {
	result, err := p.getCredential()
	if err != nil {
		return "", err
	}
	return result.Value.GetAccessToken(), nil
}

// GetCredential 实现 IDaaSCredentialProvider 接口
func (p *HumanFederatedOidcTokenProvider) GetCredential() (credential.IDaaSCredential, error) {
	result, err := p.getCredential()
	if err != nil {
		return nil, err
	}
	return &result.Value, nil
}

// getCredential 获取凭证（带缓存和刷新逻辑）
func (p *HumanFederatedOidcTokenProvider) getCredential() (*cache.RefreshResult[credential.IDaaSTokenResponse], error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.firstStartup {
		// 首次启动，尝试复用本地缓存
		localCacheResult := p.tryReuseLocalCache()
		if localCacheResult != nil {
			p.firstStartup = false
			p.cachedResult = localCacheResult
			return localCacheResult, nil
		}

		// 没有缓存，执行 Device Code 流程
		tokenResponse, err := p.getTokenWithDeviceAuthorization()
		if err != nil {
			return nil, err
		}

		// 计算 staleTime 和 prefetchTime
		expiresAt := tokenResponse.ReceivedAt.Add(time.Duration(tokenResponse.ExpiresIn) * time.Second)
		staleTime := expiresAt.Add(-time.Duration(tokenResponse.ExpiresIn/5) * time.Second)

		log.Printf("[INFO] token authn time timestamp=%d", time.Now().UnixMilli())

		// 写入本地缓存
		p.writeToLocalCache(tokenResponse)

		p.cachedResult = &cache.RefreshResult[credential.IDaaSTokenResponse]{
			Value:     *tokenResponse,
			ExpiresAt: staleTime,
		}
		p.firstStartup = false
		return p.cachedResult, nil
	} else {
		// 非首次启动，使用 refresh_token 刷新
		if p.cachedResult == nil {
			return nil, sdkerrors.NewClientError("CachedResultNotFound", "Cached result not found", nil)
		}

		refreshToken := p.cachedResult.Value.GetRefreshToken()
		if refreshToken == "" {
			return nil, sdkerrors.NewClientError("RefreshTokenEmpty", "refresh token is empty", nil)
		}

		tokenResponse, err := p.refreshToken(refreshToken)
		if err != nil {
			return nil, err
		}

		// 计算 staleTime 和 prefetchTime
		expiresAt := tokenResponse.ReceivedAt.Add(time.Duration(tokenResponse.ExpiresIn) * time.Second)
		staleTime := expiresAt.Add(-time.Duration(tokenResponse.ExpiresIn/5) * time.Second)

		log.Printf("[INFO] token refresh time timestamp=%d", time.Now().UnixMilli())

		// 每次刷新都写入本地缓存
		p.writeToLocalCache(tokenResponse)

		p.cachedResult = &cache.RefreshResult[credential.IDaaSTokenResponse]{
			Value:     *tokenResponse,
			ExpiresAt: staleTime,
		}
		return p.cachedResult, nil
	}
}

// tryReuseLocalCache 尝试复用本地缓存
func (p *HumanFederatedOidcTokenProvider) tryReuseLocalCache() *cache.RefreshResult[credential.IDaaSTokenResponse] {
	data, err := util.ReadFile(p.localHumanCachePath)
	if err != nil {
		log.Printf("[DEBUG] Read local cache failed error=%s", err.Error())
		return nil
	}

	var localToken credential.IDaaSTokenResponse
	if err := json.Unmarshal(data, &localToken); err != nil {
		log.Printf("[DEBUG] Parse local cache failed error=%s", err.Error())
		return nil
	}

	// 验证 token 是否有效
	if localToken.GetAccessToken() == "" {
		return nil
	}

	// 检查是否即将过期（提前 1/3 过期时间认为即将过期）
	thresholdSeconds := localToken.ExpiresIn / 3
	if localToken.WillSoonExpire(thresholdSeconds) {
		refreshToken := localToken.GetRefreshToken()
		if refreshToken == "" {
			return nil
		}

		tokenResponse, err := p.refreshToken(refreshToken)
		if err != nil {
			log.Printf("[DEBUG] Refresh token failed error=%s", err.Error())
			return nil
		}

		expiresAt := tokenResponse.ReceivedAt.Add(time.Duration(tokenResponse.ExpiresIn) * time.Second)
		staleTime := expiresAt.Add(-time.Duration(tokenResponse.ExpiresIn/5) * time.Second)

		log.Printf("[INFO] token refresh time timestamp=%d", time.Now().UnixMilli())

		// 写入本地缓存
		p.writeToLocalCache(tokenResponse)

		return &cache.RefreshResult[credential.IDaaSTokenResponse]{
			Value:     *tokenResponse,
			ExpiresAt: staleTime,
		}
	} else {
		expiresAt := localToken.ReceivedAt.Add(time.Duration(localToken.ExpiresIn) * time.Second)
		staleTime := expiresAt.Add(-time.Duration(localToken.ExpiresIn/5) * time.Second)

		return &cache.RefreshResult[credential.IDaaSTokenResponse]{
			Value:     localToken,
			ExpiresAt: staleTime,
		}
	}
}

// getTokenWithDeviceAuthorization 通过 Device Code 流程获取令牌
func (p *HumanFederatedOidcTokenProvider) getTokenWithDeviceAuthorization() (*credential.IDaaSTokenResponse, error) {
	// 获取 Device Code
	deviceCodeResponse, err := p.oauth2Util.GetDeviceCode(
		p.deviceAuthorizationEndpoint,
		p.clientId,
		p.scope,
	)
	if err != nil {
		return nil, err
	}

	// 打开浏览器使用 VerificationURIComplete（含 user_code，免去用户手输），
	// 但日志只记录不含 user_code 的 VerificationURI，避免一次性授权码被持久化到
	// 集中式日志后被他人用于完成授权（RFC 8628 §5.2 安全考量）。
	verificationURI := deviceCodeResponse.VerificationURIComplete
	if verificationURI == "" {
		verificationURI = deviceCodeResponse.VerificationURI
	}

	log.Printf("[INFO] Open the verification URL in your browser url=%s", verificationURI)

	// 尝试打开浏览器（使用 complete URL；失败日志同样只记录不含 code 的 URL）
	if err := util.OpenBrowser(verificationURI); err != nil {
		log.Printf("[WARN] Open browser failed error=%s url=%s", err.Error(), verificationURI)
	}

	// 轮询获取令牌。优先尊重服务端返回的 expires_at / expires_in，缺失时再使用默认等待上限。
	pollInterval := deviceCodeResponse.Interval
	if pollInterval <= 0 {
		pollInterval = DefaultPollInterval
	}
	deadline := resolveDeviceCodeDeadline(deviceCodeResponse.ExpiresAt, deviceCodeResponse.ExpiresIn)

	for time.Now().Before(deadline) {
		sleepDuration := time.Duration(pollInterval) * time.Second
		if remaining := time.Until(deadline); remaining < sleepDuration {
			sleepDuration = remaining
		}
		if sleepDuration <= 0 {
			break
		}
		time.Sleep(sleepDuration)

		token, err := p.oauth2Util.GetTokenByDeviceCode(
			p.tokenEndpoint,
			p.clientId,
			deviceCodeResponse.DeviceCode,
		)
		if err != nil {
			// 优先识别 OAuth2 标准 error code（RFC 8628 §3.5）：
			//   authorization_pending → 用户尚未完成授权，继续 poll
			//   slow_down             → 服务端要求降低 poll 频率，应增加 interval
			//   access_denied         → 用户拒绝授权，立即终止
			//   expired_token         → device_code 已过期，立即终止
			//   其它 OAuth2 错误      → 立即抛出
			var oauth2Err *sdkerrors.OAuth2Error
			if errors.As(err, &oauth2Err) {
				switch oauth2Err.OAuthCode {
				case "authorization_pending":
					continue
				case "slow_down":
					pollInterval += 5
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
			// 兼容降级：非标 OAuth2 响应但仍是 HTTP 400 → 视为 pending（与旧行为保持兼容）
			var httpErr *sdkerrors.HttpError
			if errors.As(err, &httpErr) && httpErr.StatusCode == 400 {
				continue
			}
			return nil, err
		}

		if token != nil && token.GetAccessToken() != "" {
			return token, nil
		}
	}

	return nil, sdkerrors.NewClientError("DeviceCodeTimeout", "waiting for token timeout", nil)
}

// resolveDeviceCodeDeadline 计算 device flow 轮询截止时间。
//
// 优先级：服务端绝对过期时间 expires_at > 相对过期时间 expires_in > 默认上限。
// expires_at 必须晚于当前时间才采用，否则（时钟漂移 / 服务端异常返回过去的时间戳）
// 直接使用会导致一次轮询都不进入就立即超时，因此回退到 expires_in 或默认上限。
func resolveDeviceCodeDeadline(expiresAt int64, expiresIn int64) time.Time {
	now := time.Now()
	if expiresAt > 0 {
		deadline := time.Unix(expiresAt, 0)
		if deadline.After(now) {
			return deadline
		}
	}
	if expiresIn > 0 {
		return now.Add(time.Duration(expiresIn) * time.Second)
	}
	return now.Add(MaxWaitIntervalSeconds * time.Second)
}

// refreshToken 通过 refresh_token 刷新令牌
func (p *HumanFederatedOidcTokenProvider) refreshToken(refreshToken string) (*credential.IDaaSTokenResponse, error) {
	return p.oauth2Util.RefreshToken(
		p.tokenEndpoint,
		p.clientId,
		refreshToken,
	)
}

// writeToLocalCache 写入本地缓存
func (p *HumanFederatedOidcTokenProvider) writeToLocalCache(token *credential.IDaaSTokenResponse) {
	data, err := json.Marshal(token)
	if err != nil {
		log.Printf("[WARN] Marshal token failed error=%s", err.Error())
		return
	}

	// 确保目录存在；使用 0700（drwx------），仅当前用户可访问，
	// 防止同机器其他账号通过 ls 枚举或读取目录下的 token 文件。
	cacheDir := filepath.Dir(p.localHumanCachePath)
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		log.Printf("[WARN] Create cache directory failed error=%s", err.Error())
		return
	}

	if err := util.WriteFile(p.localHumanCachePath, data); err != nil {
		log.Printf("[WARN] Write local cache failed error=%s", err.Error())
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
