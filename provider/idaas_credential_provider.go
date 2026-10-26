package provider

import (
	"context"

	"github.com/cloud-idaas/idaas-go-core-sdk/credential"
)

type IDaaSCredentialProvider interface {
	// GetCredential 等价于 GetCredentialWithContext(context.Background())。
	// 请求链路中优先用 GetCredentialWithContext(ctx) 以支持取消与 deadline。
	GetCredential() (credential.IDaaSCredential, error)

	// GetCredentialWithContext ctx 透传至底层 HTTP 请求，上层 ctx 取消时可中断凭证刷新的网络 IO。
	GetCredentialWithContext(ctx context.Context) (credential.IDaaSCredential, error)
}
