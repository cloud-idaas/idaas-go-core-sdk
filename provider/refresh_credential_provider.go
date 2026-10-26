package provider

import "github.com/cloud-idaas/idaas-go-core-sdk/credential"

type RefreshCredentialProvider[T credential.IDaaSCredential] interface {
	IDaaSCredentialProvider

	Refresh() (T, error)
}
