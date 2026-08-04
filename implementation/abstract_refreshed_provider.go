package implementation

import (
	"github.com/cloud-idaas/idaas-go-core-sdk/cache"
	"github.com/cloud-idaas/idaas-go-core-sdk/credential"
	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
	"time"
)

// AbstractRefreshedCredentialProvider 抽象刷新凭证提供者 (§2.1 Layer3)
// 使用 Go 组合模式 + CachedResultSupplier 实现自动刷新
type AbstractRefreshedCredentialProvider struct {
	supplier *cache.CachedResultSupplier[credential.IDaaSCredential]
}

// NewAbstractRefreshedCredentialProvider 创建 AbstractRefreshedCredentialProvider
func NewAbstractRefreshedCredentialProvider(
	refreshFunc func() (*cache.RefreshResult[credential.IDaaSCredential], error),
	staleBehavior enums.StaleValueBehavior,
	prefetchThreshold time.Duration,
) *AbstractRefreshedCredentialProvider {
	return &AbstractRefreshedCredentialProvider{
		supplier: cache.NewCachedResultSupplier(refreshFunc, staleBehavior, prefetchThreshold),
	}
}

// GetCredential 获取凭证（实现 IDaaSCredentialProvider 接口）
func (p *AbstractRefreshedCredentialProvider) GetCredential() (credential.IDaaSCredential, error) {
	result, err := p.supplier.Get()
	if err != nil {
		return nil, err
	}
	return result.Value, nil
}

// Invalidate 使缓存失效
func (p *AbstractRefreshedCredentialProvider) Invalidate() {
	p.supplier.Invalidate()
}
