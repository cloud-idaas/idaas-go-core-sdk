package provider

import "github.com/aliyun/idaas-go-core-sdk/credential"

// IDaaSCredentialProvider 凭证提供者接口 (§4.2.1)
type IDaaSCredentialProvider interface {
	// GetCredential 获取凭证
	GetCredential() (credential.IDaaSCredential, error)
}
