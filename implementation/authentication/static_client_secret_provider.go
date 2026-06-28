package authentication

import (
	"time"

	"github.com/aliyun/idaas-go-core-sdk/credential"
	"github.com/aliyun/idaas-go-core-sdk/enums"
	"github.com/aliyun/idaas-go-core-sdk/errors"
	"github.com/aliyun/idaas-go-core-sdk/http"
	"github.com/aliyun/idaas-go-core-sdk/oauth2"
	"github.com/aliyun/idaas-go-core-sdk/util"
)

// StaticClientSecretAssertionProvider 静态 Client Secret 断言提供者 (§5.1-5.3)
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

// GetCredential 获取凭证
func (p *StaticClientSecretAssertionProvider) GetCredential() (credential.IDaaSCredential, error) {
	switch p.authnMethod {
	case enums.TokenAuthnMethodClientSecretBasic:
		return p.tokenUtil.GetTokenByClientCredentialsBasic(
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
		return p.tokenUtil.GetTokenByClientCredentialsJwtAssertion(
			p.tokenEndpoint,
			p.clientId,
			assertion,
			p.scope,
		)
	default:
		// 默认 client_secret_post
		return p.tokenUtil.GetTokenByClientCredentials(
			p.tokenEndpoint,
			p.clientId,
			p.clientSecret,
			p.scope,
		)
	}
}

// createHs256Assertion 用 client_secret 作为 HMAC 密钥生成 HS256 JWT 客户端断言
// 阿里云规范：iss=sub=clientId，aud=tokenEndpoint，含 jti/iat/exp，有效期不超过 30 分钟
func (p *StaticClientSecretAssertionProvider) createHs256Assertion() (string, error) {
	if p.clientSecret == "" {
		return "", errors.NewConfigError("ClientSecretNotFound", "Client secret is required for client_secret_jwt", nil)
	}
	claims := util.BuildJwtClaims(
		p.clientId,
		p.clientId,
		p.tokenEndpoint,
		5*time.Minute,
	)
	return util.SignJwtHS256(claims, []byte(p.clientSecret))
}
