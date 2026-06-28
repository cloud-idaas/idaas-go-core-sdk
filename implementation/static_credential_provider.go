package implementation

import "github.com/aliyun/idaas-go-core-sdk/credential"

// StaticIDaaSCredentialProvider 静态凭证提供者（测试用） (§4.2.3)
type StaticIDaaSCredentialProvider struct {
	credential credential.IDaaSCredential
}

// NewStaticIDaaSCredentialProvider 创建静态凭证提供者
func NewStaticIDaaSCredentialProvider(cred credential.IDaaSCredential) *StaticIDaaSCredentialProvider {
	return &StaticIDaaSCredentialProvider{
		credential: cred,
	}
}

// GetCredential 获取凭证
func (p *StaticIDaaSCredentialProvider) GetCredential() (credential.IDaaSCredential, error) {
	return p.credential, nil
}
