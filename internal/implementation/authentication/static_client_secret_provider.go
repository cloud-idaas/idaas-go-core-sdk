package authentication

import (
	"context"

	"github.com/cloud-idaas/idaas-go-core-sdk/constants"
	"github.com/cloud-idaas/idaas-go-core-sdk/credential"
	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
	"github.com/cloud-idaas/idaas-go-core-sdk/errors"
	"github.com/cloud-idaas/idaas-go-core-sdk/http"
	"github.com/cloud-idaas/idaas-go-core-sdk/oauth2"
	"github.com/cloud-idaas/idaas-go-core-sdk/util"
)

// StaticClientSecretAssertionProvider 静态 Client Secret 断言提供者 (-5.3)
// 支持 client_secret_basic / client_secret_post / client_secret_jwt 三种认证方式
type StaticClientSecretAssertionProvider struct {
	clientId      string
	clientSecret  string
	tokenUtil     *oauth2.OAuth2TokenUtil
	scope         string
	tokenEndpoint string
	authnMethod   enums.TokenAuthnMethod
}

// NewStaticClientSecretAssertionProvider 创建 StaticClientSecretAssertionProvider
func NewStaticClientSecretAssertionProvider(
	clientId string,
	clientSecret string,
	tokenEndpoint string,
	scope string,
	authnMethod enums.TokenAuthnMethod,
	httpClient http.HttpClient,
) *StaticClientSecretAssertionProvider {
	return &StaticClientSecretAssertionProvider{
		clientId:      clientId,
		clientSecret:  clientSecret,
		tokenEndpoint: tokenEndpoint,
		scope:         scope,
		authnMethod:   authnMethod,
		tokenUtil:     oauth2.NewOAuth2TokenUtil(httpClient),
	}
}

// GetCredential 获取凭证。内部委托给 GetCredentialWithContext,使用 context.Background()。
func (p *StaticClientSecretAssertionProvider) GetCredential() (credential.IDaaSCredential, error) {
	return p.GetCredentialWithContext(context.Background())
}

// GetCredentialWithContext 获取凭证,带 context。ctx 透传到 token endpoint 请求。
func (p *StaticClientSecretAssertionProvider) GetCredentialWithContext(ctx context.Context) (credential.IDaaSCredential, error) {
	switch p.authnMethod {
	case enums.TokenAuthnMethodClientSecretBasic:
		return p.tokenUtil.GetTokenByClientCredentialsBasicWithContext(
			ctx,
			p.tokenEndpoint,
			p.clientId,
			p.clientSecret,
			p.scope,
		)
	case enums.TokenAuthnMethodClientSecretJwt:
		// 用 client_secret 对 JWT 做 HS256 签名后作为 client_assertion 提交
		assertion, err := p.createHs256Assertion()
		if err != nil {
			return nil, err
		}
		return p.tokenUtil.GetTokenByClientCredentialsJwtAssertionWithContext(
			ctx,
			p.tokenEndpoint,
			p.clientId,
			assertion,
			p.scope,
		)
	default:
		// 默认 client_secret_post
		return p.tokenUtil.GetTokenByClientCredentialsWithContext(
			ctx,
			p.tokenEndpoint,
			p.clientId,
			p.clientSecret,
			p.scope,
		)
	}
}

// createHs256Assertion 用 client_secret 作为 HMAC 密钥生成 HS256 JWT 客户端断言
// 阿里云规范：iss=sub=clientId，aud=tokenEndpoint，含 jti/iat/exp，有效期不超过 30 分钟
//
// client_secret 是 string(不可变,源串待 GC)。这里派生的 keyBytes 副本由
// SignJwtHS256 内部 defer ClearBytes 清零(见 util 包文档"敏感 []byte 清零约定")。
func (p *StaticClientSecretAssertionProvider) createHs256Assertion() (string, error) {
	if p.clientSecret == "" {
		return "", errors.NewConfigError(constants.ClientSecretNotFound, "Client secret is required for client_secret_jwt", nil)
	}
	claims := util.BuildJwtClaims(
		p.clientId,
		p.clientId,
		p.tokenEndpoint,
		util.DefaultClientAssertionTTL,
	)
	// []byte(p.clientSecret) 派生 fresh 堆副本;SignJwtHS256 用毕即清零它。
	return util.SignJwtHS256(claims, []byte(p.clientSecret))
}
