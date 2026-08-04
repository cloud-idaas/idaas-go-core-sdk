package implementation

import (
	"github.com/cloud-idaas/idaas-go-core-sdk/credential"
	"github.com/cloud-idaas/idaas-go-core-sdk/http"
	"github.com/cloud-idaas/idaas-go-core-sdk/oauth2"
)

// IDaaSMachineTokenExchangeCredentialProvider 机器令牌交换凭证提供者 (§2.1 Layer3)
// 支持 7 种方式/6个方法
type IDaaSMachineTokenExchangeCredentialProvider struct {
	tokenUtil     *oauth2.OAuth2TokenUtil
	clientId      string
	clientSecret  string
	tokenEndpoint string
}

// NewIDaaSMachineTokenExchangeCredentialProvider 创建 IDaaSMachineTokenExchangeCredentialProvider
func NewIDaaSMachineTokenExchangeCredentialProvider(
	clientId string,
	clientSecret string,
	tokenEndpoint string,
	httpClient http.HttpClient,
) *IDaaSMachineTokenExchangeCredentialProvider {
	return &IDaaSMachineTokenExchangeCredentialProvider{
		tokenUtil:     oauth2.NewOAuth2TokenUtil(httpClient),
		clientId:      clientId,
		clientSecret:  clientSecret,
		tokenEndpoint: tokenEndpoint,
	}
}

// ExchangeToken 交换令牌
func (p *IDaaSMachineTokenExchangeCredentialProvider) ExchangeToken(
	subjectToken string,
	actorToken string,
) (credential.IDaaSCredential, error) {
	return p.tokenUtil.TokenExchange(
		p.tokenEndpoint,
		p.clientId,
		p.clientSecret,
		subjectToken,
		"urn:ietf:params:oauth:token-type:access_token",
		actorToken,
		"urn:ietf:params:oauth:token-type:access_token",
		"urn:ietf:params:oauth:token-type:access_token",
		"",
	)
}
