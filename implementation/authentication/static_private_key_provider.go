package authentication

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/cloud-idaas/idaas-go-core-sdk/credential"
	"github.com/cloud-idaas/idaas-go-core-sdk/errors"
	"github.com/cloud-idaas/idaas-go-core-sdk/http"
	"github.com/cloud-idaas/idaas-go-core-sdk/oauth2"
	"github.com/cloud-idaas/idaas-go-core-sdk/util"
)

// StaticPrivateKeyAssertionProvider 静态私钥断言提供者 (§5.4, §5.7)
type StaticPrivateKeyAssertionProvider struct {
	clientId      string
	issuer        string
	privateKey    interface{}
	tokenEndpoint string
	scope         string
	tokenUtil     *oauth2.OAuth2TokenUtil
}

// NewStaticPrivateKeyAssertionProvider 创建 StaticPrivateKeyAssertionProvider
func NewStaticPrivateKeyAssertionProvider(
	clientId string,
	issuer string,
	privateKey interface{},
	tokenEndpoint string,
	scope string,
	httpClient http.HttpClient,
) *StaticPrivateKeyAssertionProvider {
	return &StaticPrivateKeyAssertionProvider{
		clientId:      clientId,
		issuer:        issuer,
		privateKey:    privateKey,
		tokenEndpoint: tokenEndpoint,
		scope:         scope,
		tokenUtil:     oauth2.NewOAuth2TokenUtil(httpClient),
	}
}

// GetCredential 获取凭证
//
// 阿里云 IDaaS private_key_jwt 规范：
//
//	grant_type=client_credentials, client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer,
//	client_assertion=<RS256/ES256 JWT>, client_id=<clientId>
//
// 注意不要使用 RFC 7523 的 jwt-bearer grant（grant_type=urn:...:jwt-bearer + assertion=...），
// 那是另一种用 JWT 直接换 token 的 grant，阿里云 IDaaS 不接受这种方式做客户端认证，会返回 401。
func (p *StaticPrivateKeyAssertionProvider) GetCredential() (credential.IDaaSCredential, error) {
	// 构建 JWT assertion
	assertion, err := p.createAssertion()
	if err != nil {
		return nil, err
	}

	return p.tokenUtil.GetTokenByClientCredentialsJwtAssertion(
		p.tokenEndpoint,
		p.clientId,
		assertion,
		p.scope,
	)
}

// createAssertion 创建 JWT assertion
//
// 阿里云 IDaaS 规范（与 RFC 7523 §3 一致）：
//
//	iss = sub = clientId
//	aud = tokenEndpoint
//	exp 不超过 30 分钟
//
// 注意 iss 必须是 clientId 而不是 IDaaS issuer URL，否则会返回 invalid_issuer。
func (p *StaticPrivateKeyAssertionProvider) createAssertion() (string, error) {
	claims := util.BuildJwtClaims(
		p.clientId,
		p.clientId,
		p.tokenEndpoint,
		5*time.Minute,
	)

	switch key := p.privateKey.(type) {
	case *rsa.PrivateKey:
		return util.SignJwtRS256(claims, key)
	case *ecdsa.PrivateKey:
		return util.SignJwtES256(claims, key)
	default:
		// 严禁静默返回空字符串：调用方拿到空 assertion 提交后，服务器会回 invalid_client，
		// 用户根本看不出来是密钥类型不对。这里直接抛出结构化错误以便排查。
		return "", errors.NewConfigError(
			"UnsupportedPrivateKeyType",
			fmt.Sprintf("unsupported private key type %T (expected *rsa.PrivateKey or *ecdsa.PrivateKey)", p.privateKey),
			nil,
		)
	}
}
