package provider

import "github.com/cloud-idaas/idaas-go-core-sdk/credential"

// IDaaSTokenExchangeCredentialProvider 令牌交换凭证提供者接口 (§4.2.2)
type IDaaSTokenExchangeCredentialProvider interface {
	// ExchangeToken 交换令牌
	ExchangeToken(subjectToken string, actorToken string) (credential.IDaaSCredential, error)
}
