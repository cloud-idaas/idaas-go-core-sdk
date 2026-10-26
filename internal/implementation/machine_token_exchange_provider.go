package implementation

import (
	"context"
	"strings"

	"github.com/cloud-idaas/idaas-go-core-sdk/config"
	"github.com/cloud-idaas/idaas-go-core-sdk/constants"
	"github.com/cloud-idaas/idaas-go-core-sdk/credential"
	"github.com/cloud-idaas/idaas-go-core-sdk/errors"
	"github.com/cloud-idaas/idaas-go-core-sdk/http"
	"github.com/cloud-idaas/idaas-go-core-sdk/oauth2"
	"github.com/cloud-idaas/idaas-go-core-sdk/provider"
)

// IDaaSMachineTokenExchangeCredentialProvider 机器令牌交换凭证提供者 ( Layer3)
//
// 客户端认证与 Java SDK 一致，支持 PLUGIN 以外的全部 authn method：
// client_secret_basic / client_secret_post / client_secret_jwt / private_key_jwt / PCA / PKCS7 / OIDC。
// 认证材料（secret、私钥、attested document、OIDC token）在每次请求时读取，凭证轮换后无需重建 provider。
//
// 重构:ExchangeToken 签名由 (subjectToken, actorToken string) 改为
// (req TokenExchangeRequest),token type 参数化,不再硬编码。
type IDaaSMachineTokenExchangeCredentialProvider struct {
	tokenUtil  *oauth2.OAuth2TokenUtil
	config     *config.IDaaSClientConfig
	httpClient http.HttpClient
	// scope 构造时绑定；req.Scope 为空时使用它 (与 machine provider 的 一致)。
	scope string
}

// NewIDaaSMachineTokenExchangeCredentialProvider 创建 IDaaSMachineTokenExchangeCredentialProvider。
// scope 是 req.Scope 为空时发送的默认 scope。
func NewIDaaSMachineTokenExchangeCredentialProvider(
	cfg *config.IDaaSClientConfig,
	scope string,
	httpClient http.HttpClient,
) *IDaaSMachineTokenExchangeCredentialProvider {
	return &IDaaSMachineTokenExchangeCredentialProvider{
		tokenUtil:  oauth2.NewOAuth2TokenUtil(httpClient),
		config:     cfg,
		httpClient: httpClient,
		scope:      scope,
	}
}

// ExchangeToken 交换令牌。内部委托给 ExchangeTokenWithContext。
func (p *IDaaSMachineTokenExchangeCredentialProvider) ExchangeToken(
	req provider.TokenExchangeRequest,
) (credential.IDaaSCredential, error) {
	return p.ExchangeTokenWithContext(context.Background(), req)
}

// ExchangeTokenWithContext 交换令牌,带 context。
// ctx 透传到 token endpoint 请求,使令牌交换可被上层请求取消。
func (p *IDaaSMachineTokenExchangeCredentialProvider) ExchangeTokenWithContext(
	ctx context.Context,
	req provider.TokenExchangeRequest,
) (credential.IDaaSCredential, error) {
	// RFC 8693：subject_token 为 REQUIRED。空值在客户端拦截（ClientError），
	// 不再原样发往服务端——省一次网络往返，且负例行为不依赖服务端是否严格。
	if strings.TrimSpace(req.SubjectToken) == "" {
		return nil, errors.NewClientError(
			constants.SubjectTokenNotFound,
			"subject_token is required for RFC 8693 token exchange (rejected client-side, no request sent)",
			nil,
		)
	}

	auth, err := buildClientAuthentication(ctx, p.config, p.httpClient)
	if err != nil {
		return nil, err
	}

	// token type 默认值:urn:ietf:params:oauth:token-type:access_token
	subjectTokenType := req.SubjectTokenType
	if subjectTokenType == "" {
		subjectTokenType = "urn:ietf:params:oauth:token-type:access_token"
	}
	actorTokenType := req.ActorTokenType
	if actorTokenType == "" && req.ActorToken != "" {
		actorTokenType = "urn:ietf:params:oauth:token-type:access_token"
	}
	scope := req.Scope
	if scope == "" {
		scope = p.scope
	}

	return p.tokenUtil.TokenExchangeWithClientAuthWithContext(
		ctx,
		p.config.TokenEndpoint,
		auth,
		req.SubjectToken,
		subjectTokenType,
		req.ActorToken,
		actorTokenType,
		req.RequestedTokenType,
		scope,
	)
}
