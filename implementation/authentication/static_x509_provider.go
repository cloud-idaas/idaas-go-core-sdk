package authentication

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"time"

	"github.com/aliyun/idaas-go-core-sdk/credential"
	"github.com/aliyun/idaas-go-core-sdk/errors"
	"github.com/aliyun/idaas-go-core-sdk/http"
	"github.com/aliyun/idaas-go-core-sdk/oauth2"
	"github.com/aliyun/idaas-go-core-sdk/util"
)

// StaticX509AssertionProvider PrivateCA X509 证书认证提供者（PCA）
//
// 阿里云 IDaaS 私有协议：client_assertion 为用 PEM 私钥签发的 RS256 / ES256 JWT；
// 同时提交 client_x509（叶子证书）、client_x509_chain（中间证书链）、
// application_federated_credential_name 用于服务端定位联邦凭证并验链。
//
// JWT claims（与 Java SDK StaticPrivateKeyAssertionProvider 对齐）：
//
//	iss = sub = clientId
//	aud = tokenEndpoint
type StaticX509AssertionProvider struct {
	clientId                string
	privateKey              interface{}
	clientX509              string
	clientX509Chain         string
	federatedCredentialName string
	tokenEndpoint           string
	scope                   string
	tokenUtil               *oauth2.OAuth2TokenUtil
}

// NewStaticX509AssertionProvider 创建 StaticX509AssertionProvider
func NewStaticX509AssertionProvider(
	clientId string,
	privateKey interface{},
	clientX509 string,
	clientX509Chain string,
	federatedCredentialName string,
	tokenEndpoint string,
	scope string,
	httpClient http.HttpClient,
) *StaticX509AssertionProvider {
	return &StaticX509AssertionProvider{
		clientId:                clientId,
		privateKey:              privateKey,
		clientX509:              clientX509,
		clientX509Chain:         clientX509Chain,
		federatedCredentialName: federatedCredentialName,
		tokenEndpoint:           tokenEndpoint,
		scope:                   scope,
		tokenUtil:               oauth2.NewOAuth2TokenUtil(httpClient),
	}
}

// GetCredential 获取凭证
func (p *StaticX509AssertionProvider) GetCredential() (credential.IDaaSCredential, error) {
	if p.clientX509 == "" {
		return nil, errors.NewConfigError(
			"ClientX509CertificateNotFound",
			"client_x509 (leaf certificate PEM) is required for PCA authentication",
			nil,
		)
	}

	assertion, err := p.createAssertion()
	if err != nil {
		return nil, err
	}

	return p.tokenUtil.GetTokenByX509JwtBearer(
		p.tokenEndpoint,
		p.clientId,
		assertion,
		p.clientX509,
		p.clientX509Chain,
		p.federatedCredentialName,
		p.scope,
	)
}

// createAssertion 用 PEM 私钥签发客户端 JWT 断言
//
// 与 Java SDK StaticPrivateKeyAssertionProvider.getClientAssertion() 完全对齐：
// iss = sub = clientId, aud = tokenEndpoint
func (p *StaticX509AssertionProvider) createAssertion() (string, error) {
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
		return "", errors.NewConfigError(
			"UnsupportedPrivateKeyType",
			"PCA only supports RSA or ECDSA private key",
			nil,
		)
	}
}
