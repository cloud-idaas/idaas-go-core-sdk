package factory

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/cloud-idaas/idaas-go-core-sdk/credential"
	"github.com/cloud-idaas/idaas-go-core-sdk/provider"
)

// closeableFakeProvider 是实现 IDaaSCredentialProvider 且带 Close() error 的 stub,
// 用于验证 factory.Reset() 释放 provider 时会调用其 Close。
type closeableFakeProvider struct {
	closed int32 // atomic
}

func (p *closeableFakeProvider) GetCredential() (credential.IDaaSCredential, error) {
	return nil, nil
}
func (p *closeableFakeProvider) GetCredentialWithContext(ctx context.Context) (credential.IDaaSCredential, error) {
	return nil, nil
}
func (p *closeableFakeProvider) Close() error {
	atomic.AddInt32(&p.closed, 1)
	return nil
}

// nonCloseableFakeProvider 不实现 Close,验证 Reset 不会 panic 且跳过它。
type nonCloseableFakeProvider struct{}

func (p *nonCloseableFakeProvider) GetCredential() (credential.IDaaSCredential, error) {
	return nil, nil
}
func (p *nonCloseableFakeProvider) GetCredentialWithContext(ctx context.Context) (credential.IDaaSCredential, error) {
	return nil, nil
}

// 编译期断言两个 stub 都满足 provider 接口。
var (
	_ provider.IDaaSCredentialProvider = (*closeableFakeProvider)(nil)
	_ provider.IDaaSCredentialProvider = (*nonCloseableFakeProvider)(nil)
)

// TestFactory_Reset_ClosesCloserProviders 验证:
// Reset 必须对实现了 Close() error 的 provider 调用其 Close,
// 否则注入的 PrefetchStrategy / 后台 goroutine 在 Reset 后泄漏。
//
// 直接把 stub 注入 f.providers(同包测试),无需走真实 Initialize,
// 把"是否调用 Close"从 factory 自身行为中隔离出来,排除 HTTP/网络依赖。
func TestFactory_Reset_ClosesCloserProviders(t *testing.T) {
	Reset()
	defer Reset()

	f := GetInstance()
	// 假装已初始化,但绕过真实 provider 构建:Reset 走"清空 providers + Close" 分支。
	withCloser := &closeableFakeProvider{}
	withoutCloser := &nonCloseableFakeProvider{}

	f.mu.Lock()
	f.initialized = true
	f.providers = map[string]provider.IDaaSCredentialProvider{
		"closer":   withCloser,
		"nocloser": withoutCloser,
	}
	f.mu.Unlock()

	f.Reset()

	if got := atomic.LoadInt32(&withCloser.closed); got != 1 {
		t.Errorf("expected Close to be called exactly once on closer provider, got %d", got)
	}
	if f.IsInitialized() {
		t.Error("factory should be reset to uninitialized")
	}
}

// TestFactory_Reset_NilWhenNoProviders 验证 Reset 在无 provider / 无预热 goroutine 时
// 不会 panic(nil-safe:warmupCancel/warmupDone 为 nil 时跳过 select)。
func TestFactory_Reset_NilWhenNoProviders(t *testing.T) {
	Reset()
	defer Reset()

	f := GetInstance()
	f.mu.Lock()
	f.initialized = true
	f.providers = nil
	f.exchangeProviders = nil
	f.warmupCancel = nil
	f.warmupDone = nil
	f.mu.Unlock()

	// 不应 panic。
	f.Reset()

	if f.IsInitialized() {
		t.Error("expected initialized=false after Reset")
	}
}
