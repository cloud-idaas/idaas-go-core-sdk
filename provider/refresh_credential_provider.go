package provider

import "github.com/cloud-idaas/idaas-go-core-sdk/credential"

// RefreshCredentialProvider 可刷新凭证提供者接口 (§4.2.3)
type RefreshCredentialProvider[T credential.IDaaSCredential] interface {
	IDaaSCredentialProvider

	// Refresh 刷新凭证
	Refresh() (T, error)
}
