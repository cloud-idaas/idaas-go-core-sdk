package authentication

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aliyun/idaas-go-core-sdk/constants"
	"github.com/aliyun/idaas-go-core-sdk/domain"
	"github.com/aliyun/idaas-go-core-sdk/enums"
	"github.com/aliyun/idaas-go-core-sdk/errors"
	"github.com/aliyun/idaas-go-core-sdk/http"
)

// AzureVmOidcTokenProvider Azure VM Managed Identity OIDC Token 提供者
//
// 通过 Azure IMDS（Instance Metadata Service）获取 Managed Identity ID Token，用于 IDaaS OIDC 联邦认证：
//
//	GET http://169.254.169.254/metadata/identity/oauth2/token
//	    ?api-version=2018-02-01&resource=<URL-encoded resource>
//	Header: Metadata: true
//
// 参考：https://learn.microsoft.com/azure/active-directory/managed-identities-azure-resources/how-to-use-vm-token
//
// 适用场景：authnMethod = OIDC、clientDeployEnvironment = AZURE_VM
//
// 实现细节：
//  1. resource 由调用方传入，写入 token 的 aud claim（约定为 IDaaS issuer endpoint 的 origin）
//  2. IMDS 返回 JSON 包装：{"access_token":"<JWT>", "expires_on":"<unix秒字符串>", ...}
//  3. 缓存策略：使用 expires_on 字段（unix 秒）判断过期；过期前 10 分钟主动刷新
//     若 expires_on 解析失败，回退到解析 JWT payload 的 exp；都失败则禁用缓存
type AzureVmOidcTokenProvider struct {
	httpClient http.HttpClient
	resource   string

	mu          sync.Mutex
	cachedToken string
	expiresAt   int64 // unix 秒
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

// NewAzureVmOidcTokenProvider 创建 AzureVmOidcTokenProvider
//
// resource：写入 ID Token aud claim 的值，通常传入 IDaaS issuer endpoint 的 origin（必填）
// httpClient：HTTP 客户端（必填）
func NewAzureVmOidcTokenProvider(httpClient http.HttpClient, resource string) *AzureVmOidcTokenProvider {
	return &AzureVmOidcTokenProvider{
		httpClient: httpClient,
		resource:   resource,
	}
}

// GetOidcToken 获取 OIDC Token（带轻量缓存，过期前 10 分钟刷新）
func (p *AzureVmOidcTokenProvider) GetOidcToken() (string, error) {
	if p.resource == "" {
		return "", errors.NewConfigError(
			"OidcResourceNotFound",
			"resource is required for Azure VM OIDC token (typically the IDaaS issuer endpoint origin)",
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

	tokenUrl := fmt.Sprintf(constants.AzureVmIdentityTokenUrlTemplate, url.QueryEscape(p.resource))
	resp, err := p.httpClient.Execute(&domain.HttpRequest{
		Method: enums.HttpMethodGet,
		URL:    tokenUrl,
		Headers: map[string]string{
			constants.HeaderMetadata: constants.HeaderMetadataValueTrue,
		},
	})
	if err != nil {
		return "", errors.NewCredentialError(
			"AzureVmIdentityTokenFetchFailed",
			fmt.Sprintf("Failed to fetch Azure VM identity token: %s", err.Error()),
			err,
		)
	}
	if !resp.IsSuccess() {
		return "", errors.NewHttpError(
			"ClientError",
			fmt.Sprintf("Failed to fetch Azure VM identity token (HTTP %d): %s", resp.StatusCode, string(resp.Body)),
			resp.StatusCode,
			nil,
		)
	}

	var imdsResp azureImdsTokenResponse
	if err := json.Unmarshal(resp.Body, &imdsResp); err != nil {
		return "", errors.NewCredentialError(
			"AzureVmIdentityTokenInvalidJson",
			fmt.Sprintf("Failed to parse Azure VM identity token JSON: %s", err.Error()),
			err,
		)
	}

	token := strings.TrimSpace(imdsResp.AccessToken)
	if token == "" {
		return "", errors.NewCredentialError(
			"AzureVmIdentityTokenEmpty",
			"Azure VM identity token response missing access_token field",
			nil,
		)
	}

	p.mu.Lock()
	p.cachedToken = token
	p.expiresAt = resolveAzureTokenExpiresAt(imdsResp.ExpiresOn, token)
	p.mu.Unlock()
	return token, nil
}

// Resource 返回当前 resource 值
func (p *AzureVmOidcTokenProvider) Resource() string {
	return p.resource
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
//  1. IMDS 响应里的 expires_on（unix 秒字符串，Azure 官方推荐字段）
//  2. JWT payload 里的 exp 字段（兜底）
//  3. 都解析不出来 -> 返回 0，表示不缓存
func resolveAzureTokenExpiresAt(expiresOnStr string, jwtToken string) int64 {
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
