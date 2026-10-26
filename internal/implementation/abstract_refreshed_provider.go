package implementation

import (
	"context"

	"github.com/cloud-idaas/idaas-go-core-sdk/cache"
	"github.com/cloud-idaas/idaas-go-core-sdk/credential"
	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
)

// AbstractRefreshedCredentialProvider 抽象刷新凭证提供者 ( Layer3)
// 使用 Go 组合模式 + CachedResultSupplier 实现自动刷新
type AbstractRefreshedCredentialProvider struct {
	supplier *cache.CachedResultSupplier[credential.IDaaSCredential]
}

// NewAbstractRefreshedCredentialProvider 创建 AbstractRefreshedCredentialProvider
//
// refreshFunc 签名带 ctx:ctx 透传到刷新链路,使凭证获取可被上层请求取消。
//
// 注:旧版第三参 prefetchThreshold 已删除——该字段在构造后被设但全程
// 未被读取,属死代码。刷新时点改由 supplier 内部三时点(StaleTime/PrefetchTime/
// ExpiresAt)推导。baseCtx(宿主取消传播)请经 WithBaseContext 注入。
func NewAbstractRefreshedCredentialProvider(
	refreshFunc func(context.Context) (*cache.RefreshResult[credential.IDaaSCredential], error),
	staleBehavior enums.StaleValueBehavior,
) *AbstractRefreshedCredentialProvider {
	return &AbstractRefreshedCredentialProvider{
		supplier: cache.NewCachedResultSupplier(refreshFunc, staleBehavior),
	}
}

// WithBaseContext 注入宿主生命周期 ctx。
//
// factory 在 Initialize 时构造一个随 Reset 取消的 baseCtx,经此注入每个 provider
// 的 supplier;supplier 的后台 worker(leader 同步 worker / async worker)据此 ctx
// 感知宿主关闭,取消尚未完成的刷新。默认满足(非 opt-in)。
// baseCtx == nil 仅限非 factory 直接构造(测试)场景,回退 context.Background 零回归。
//
// Experimental:beta 阶段接入;GA 前若 baseCtx 语义统一化会调整注入层。
func (p *AbstractRefreshedCredentialProvider) WithBaseContext(ctx context.Context) *AbstractRefreshedCredentialProvider {
	if p.supplier != nil {
		p.supplier.WithBaseContext(ctx)
	}
	return p
}

// GetCredential 获取凭证（实现 IDaaSCredentialProvider 接口）。
// 内部委托给 GetCredentialWithContext,使用 context.Background()。
func (p *AbstractRefreshedCredentialProvider) GetCredential() (credential.IDaaSCredential, error) {
	return p.GetCredentialWithContext(context.Background())
}

// GetCredentialWithContext 获取凭证,带 context。
// ctx 透传到 CachedResultSupplier → refreshFunc → 底层 HTTP 请求。
//
// ALLOW 策略在过期/stale 分支有意返回 (cached, ErrStaleCredentialReturned),
// 调用方需要旧值降级:err != nil 但 result != nil && result.Value != nil 时,
// 同时返回降级凭证和错误,让调用方决定是否使用旧值;result/Value 为 nil 时仍返回 (nil, err)。
func (p *AbstractRefreshedCredentialProvider) GetCredentialWithContext(ctx context.Context) (credential.IDaaSCredential, error) {
	result, err := p.supplier.GetWithContext(ctx)
	if err != nil {
		// 降级路径:ALLOW 策略返回 (cached, ErrStaleCredentialReturned),
		// 调用方应能拿到旧值继续使用(并感知到 staleness 信号)。
		if result != nil {
			return result.Value, err
		}
		return nil, err
	}
	return result.Value, nil
}

// Invalidate 使缓存失效
func (p *AbstractRefreshedCredentialProvider) Invalidate() {
	p.supplier.Invalidate()
}

// SetScope 设置 supplier 绑定的 scope。
// 该 scope 会携带在 RefreshEvent 中，由 factory 转发给 TokenListener。
// 应在构造后、首次刷新前调用。
func (p *AbstractRefreshedCredentialProvider) SetScope(scope string) {
	if p.supplier != nil {
		p.supplier.WithScope(scope)
	}
}

// Close 释放 supplier 持有的后台资源。
//
// 注入的 PrefetchStrategy 可能持有 goroutine / ticker;provider 不再被使用时
// (如 factory Reset、进程退出)应调用 Close 释放,避免孤儿 goroutine 泄漏。
// 未注入策略时 supplier.Close 为 no-op。多次调用安全。
func (p *AbstractRefreshedCredentialProvider) Close() error {
	if p.supplier != nil {
		return p.supplier.Close()
	}
	return nil
}
