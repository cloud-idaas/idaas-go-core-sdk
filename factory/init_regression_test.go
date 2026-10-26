package factory

import (
	"sync"
	"testing"

	"github.com/cloud-idaas/idaas-go-core-sdk/constants"
	"github.com/cloud-idaas/idaas-go-core-sdk/errors"
)

// TestCreateCredentialProvider_NotInitialized 回归：未初始化时返回 NotInit 错误而不是 nil 解引用 panic。
func TestCreateCredentialProvider_NotInitialized(t *testing.T) {
	Reset()
	defer Reset()

	_, err := GetInstance().CreateCredentialProvider()
	if !errors.HasCode(err, constants.IDaaSCredentialProviderFactoryNotInit) {
		t.Fatalf("expected IDaaSCredentialProviderFactoryNotInit, got %v", err)
	}
}

// TestTokenExchangeProvider_EmptyScopeSharesDefaultKey 回归：ByScope("") 与 ByScope(cfg.Scope)
// 命中同一个 token exchange provider。
func TestTokenExchangeProvider_EmptyScopeSharesDefaultKey(t *testing.T) {
	Reset()
	defer Reset()

	cfg := validTestConfig()
	if err := InitWithConfig(cfg); err != nil {
		t.Fatalf("InitWithConfig failed: %v", err)
	}
	p1, err := GetIDaaSTokenExchangeCredentialProviderByScope("")
	if err != nil {
		t.Fatal(err)
	}
	p2, err := GetIDaaSTokenExchangeCredentialProviderByScope(cfg.Scope)
	if err != nil {
		t.Fatal(err)
	}
	if p1 != p2 {
		t.Fatal("empty scope and default scope should resolve to the same provider")
	}
}

// TestInitialize_ConcurrentFirstWins 回归：并发 Initialize 只有一份配置生效，
// 不会出现后到者覆盖已登记 provider 缓存的情况。
func TestInitialize_ConcurrentFirstWins(t *testing.T) {
	Reset()
	defer Reset()

	f := GetInstance()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := f.Initialize(validTestConfig()); err != nil {
				t.Errorf("Initialize failed: %v", err)
			}
		}()
	}
	wg.Wait()

	p1, err := f.GetIDaaSCredentialProviderByScope("")
	if err != nil {
		t.Fatal(err)
	}
	cfgBefore := f.GetConfig()
	if err := f.Initialize(validTestConfig()); err != nil {
		t.Fatal(err)
	}
	p2, _ := f.GetIDaaSCredentialProviderByScope("")
	// GetConfig 返回深拷贝(防调用方修改冻结配置),指针不再相等,
	// 故比较关键字段值来验证 re-Initialize 未替换 config 内容。
	cfgAfter := f.GetConfig()
	if p1 != p2 || cfgAfter.InstanceId != cfgBefore.InstanceId ||
		cfgAfter.ClientId != cfgBefore.ClientId || cfgAfter.Scope != cfgBefore.Scope {
		t.Fatal("re-Initialize must not replace the registered config or provider cache")
	}
}
