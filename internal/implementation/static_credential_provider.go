package implementation

import (
	"context"

	"github.com/cloud-idaas/idaas-go-core-sdk/credential"
)

// StaticIDaaSCredentialProvider 静态凭证提供者（测试用）
type StaticIDaaSCredentialProvider struct {
	credential credential.IDaaSCredential
}

// NewStaticIDaaSCredentialProvider 创建静态凭证提供者
func NewStaticIDaaSCredentialProvider(cred credential.IDaaSCredential) *StaticIDaaSCredentialProvider {
	return &StaticIDaaSCredentialProvider{
		credential: cred,
	}
}

// GetCredential 获取凭证 (内部委托给 GetCredentialWithContext)。
func (p *StaticIDaaSCredentialProvider) GetCredential() (credential.IDaaSCredential, error) {
	return p.GetCredentialWithContext(context.Background())
}

// GetCredentialWithContext 获取凭证,带 context。静态凭证不涉及网络,ctx 仅满足接口契约。
func (p *StaticIDaaSCredentialProvider) GetCredentialWithContext(_ context.Context) (credential.IDaaSCredential, error) {
	return p.credential, nil
}
