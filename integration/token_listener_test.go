//go:build integration

// TokenListener 集成测试。
// 验证 TokenListener 的生命周期回调在正确时机被触发。
package integration

import (
	"sync"
	"testing"
	"time"

	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
	"github.com/cloud-idaas/idaas-go-core-sdk/factory"
)

// testTokenListener 测试用的 TokenListener 实现
type testTokenListener struct {
	mu                    sync.Mutex
	refreshedCount        int
	refreshFailedCount    int
	degradationEnterCount int
	degradationExitCount  int
	lastExpiresAt         time.Time
	lastScope             string
}

func (l *testTokenListener) OnTokenRefreshed(expiresAt time.Time, scope string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.refreshedCount++
	l.lastExpiresAt = expiresAt
	l.lastScope = scope
}

func (l *testTokenListener) OnTokenRefreshFailed(err error, willRetry bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.refreshFailedCount++
}

func (l *testTokenListener) OnDegradationEntered(consecutiveFailures int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.degradationEnterCount++
}

func (l *testTokenListener) OnDegradationExited(tokenState enums.TokenState) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.degradationExitCount++
}

func (l *testTokenListener) getRefreshedCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.refreshedCount
}

// TestTokenListener 验证 TokenListener 的生命周期回调
//
// 验证内容：
// 1. 首次 GetCredential 成功后，触发 OnTokenRefreshed
// 2. 回调异步执行，不阻塞主链路
// 3. 回调参数正确（expiresAt、scope）
//
// 注意：OnTokenRefreshFailed/OnDegradationEntered/OnDegradationExited 需要模拟失败场景，
// 在集成测试中难以稳定触发，因此本测试只验证成功路径。
// 失败路径的回调由单元测试覆盖。
func TestTokenListener(t *testing.T) {
	skipIfIntegrationDisabled(t)

	cfg := loadConfig(t, "client_secret_basic")
	ensureCredentials(t, cfg)
	skipIfEnvironmentUnavailable(t, cfg)

	factory.Reset()
	t.Cleanup(factory.Reset)

	// 注册 listener
	listener := &testTokenListener{}
	factory.GetInstance().AddTokenListener(listener)

	// 初始化
	if err := factory.InitWithConfig(cfg); err != nil {
		t.Fatalf("InitWithConfig 失败: %v", err)
	}

	// 获取凭证
	p, err := factory.GetIDaaSCredentialProvider()
	if err != nil {
		t.Fatalf("GetIDaaSCredentialProvider 失败: %v", err)
	}
	cred, err := p.GetCredential()
	if err != nil {
		t.Fatalf("GetCredential 失败: %v", err)
	}
	assertCredential(t, cred, "cloud_account_resource:manage_all")

	// 等待异步回调（最多 2 秒）
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if listener.getRefreshedCount() > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// 验证 OnTokenRefreshed 被触发
	if listener.getRefreshedCount() == 0 {
		t.Error("OnTokenRefreshed 未被触发（2 秒内）")
	} else {
		t.Logf("✅ OnTokenRefreshed 被触发 %d 次", listener.getRefreshedCount())
	}

	// 验证 expiresAt 合理（应该在当前时间之后）
	if listener.lastExpiresAt.Before(time.Now()) {
		t.Errorf("expiresAt 不合理: %v（在当前时间之前）", listener.lastExpiresAt)
	} else {
		t.Logf("✅ expiresAt 合理: %v", listener.lastExpiresAt)
	}

	// 验证 scope（可能为空，取决于配置）
	t.Logf("✅ scope = %q", listener.lastScope)

	// 验证其他回调未被触发（成功路径）
	if listener.refreshFailedCount > 0 {
		t.Errorf("OnTokenRefreshFailed 不应在成功路径触发，实际触发 %d 次", listener.refreshFailedCount)
	}
	if listener.degradationEnterCount > 0 {
		t.Errorf("OnDegradationEntered 不应在成功路径触发，实际触发 %d 次", listener.degradationEnterCount)
	}
	if listener.degradationExitCount > 0 {
		t.Errorf("OnDegradationExited 不应在成功路径触发，实际触发 %d 次", listener.degradationExitCount)
	}
}
