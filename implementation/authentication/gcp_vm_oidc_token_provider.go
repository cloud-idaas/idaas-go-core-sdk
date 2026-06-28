package authentication

import (
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/aliyun/idaas-go-core-sdk/constants"
	"github.com/aliyun/idaas-go-core-sdk/domain"
	"github.com/aliyun/idaas-go-core-sdk/enums"
	"github.com/aliyun/idaas-go-core-sdk/errors"
	"github.com/aliyun/idaas-go-core-sdk/http"
)

// GcpVmOidcTokenProvider Google Cloud VM OIDC Token 提供者
//
// 通过 Google Cloud VM 元数据服务获取 ID Token，用于 IDaaS OIDC 联邦认证：
//
//	GET http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity
//	    ?audience=<URL-encoded audience>&format=full
//	Header: Metadata-Flavor: Google
//
// 参考：https://cloud.google.com/compute/docs/instances/verifying-instance-identity
//
// 适用场景：authnMethod = OIDC、clientDeployEnvironment = GOOGLE_VM
//
// 实现细节：
//  1. audience 由调用方传入，约定为 IDaaS 配置中的 issuer endpoint
//  2. 元数据服务返回的是 JWT 字符串（裸 token，非 JSON）
//  3. 复用 parseJwtExpiration（与 FileOidcTokenProvider 一致）解析 exp，过期前 10 分钟刷新
type GcpVmOidcTokenProvider struct {
	httpClient http.HttpClient
	audience   string

	mu          sync.Mutex
	cachedToken string
	expiresAt   int64 // unix 秒
}

// NewGcpVmOidcTokenProvider 创建 GcpVmOidcTokenProvider
//
// audience：写入 ID Token aud claim 的值，通常传入 IDaaS issuer endpoint（必填）
// httpClient：HTTP 客户端（必填）
func NewGcpVmOidcTokenProvider(httpClient http.HttpClient, audience string) *GcpVmOidcTokenProvider {
	return &GcpVmOidcTokenProvider{
		httpClient: httpClient,
		audience:   audience,
	}
}

// GetOidcToken 获取 OIDC Token（带轻量缓存，过期前 10 分钟刷新）
func (p *GcpVmOidcTokenProvider) GetOidcToken() (string, error) {
	if p.audience == "" {
		return "", errors.NewConfigError(
			"OidcAudienceNotFound",
			"audience is required for GCP VM OIDC token (typically the IDaaS issuer endpoint)",
			nil,
		)
	}

	p.mu.Lock()
	if p.cachedToken != "" && !p.willSoonExpire() {
		token := p.cachedToken
		p.mu.Unlock()
		return token, nil
	}
	p.mu.Unlock()

	tokenUrl := fmt.Sprintf(constants.GcpVmIdentityTokenUrlTemplate, url.QueryEscape(p.audience))
	resp, err := p.httpClient.Execute(&domain.HttpRequest{
		Method: enums.HttpMethodGet,
		URL:    tokenUrl,
		Headers: map[string]string{
			constants.HeaderMetadataFlavor: constants.HeaderMetadataFlavorValueGoogle,
		},
	})
	if err != nil {
		return "", errors.NewCredentialError(
			"GcpVmIdentityTokenFetchFailed",
			fmt.Sprintf("Failed to fetch GCP VM identity token: %s", err.Error()),
			err,
		)
	}
	if !resp.IsSuccess() {
		return "", errors.NewHttpError(
			"ClientError",
			fmt.Sprintf("Failed to fetch GCP VM identity token (HTTP %d): %s", resp.StatusCode, string(resp.Body)),
			resp.StatusCode,
			nil,
		)
	}

	token := strings.TrimSpace(string(resp.Body))
	if token == "" {
		return "", errors.NewCredentialError(
			"GcpVmIdentityTokenEmpty",
			"GCP VM identity token response body is empty",
			nil,
		)
	}

	exp, err := parseJwtExpiration(token)
	if err != nil {
		// JWT 解析失败不阻断使用：缓存 token 但禁用 exp 缓存策略（每次都重新拉取）
		exp = 0
	}

	p.mu.Lock()
	p.cachedToken = token
	p.expiresAt = exp
	p.mu.Unlock()
	return token, nil
}

// Audience 返回当前 audience 值
func (p *GcpVmOidcTokenProvider) Audience() string {
	return p.audience
}

// willSoonExpire 判断 token 是否即将在缓冲时间内过期
func (p *GcpVmOidcTokenProvider) willSoonExpire() bool {
	if p.expiresAt <= 0 {
		return true
	}
	now := time.Now().Unix()
	return (p.expiresAt - now) < constants.TokenRefreshBufferSeconds
}
