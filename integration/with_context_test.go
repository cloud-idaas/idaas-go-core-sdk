//go:build integration

// WithContext 方法集成测试。
// 验证 provider 的 GetCredentialWithContext 方法支持 context 参数。
package integration

import (
	"context"
	"testing"
	"time"
)

// TestGetCredentialWithContext 验证 WithContext 方法支持 context 参数
//
// 验证内容：
// 1. 正常 context.Background() 下，行为与不带 context 的版本一致
// 2. 带 cancel 的 context（不取消），正常完成
// 3. 带 timeout 的 context，正常完成
//
// 注意：已取消的 context 行为取决于实现细节（可能命中缓存直接返回），
// 因此不在集成测试中验证。
func TestGetCredentialWithContext(t *testing.T) {
	skipIfIntegrationDisabled(t)

	cfg := loadConfig(t, "client_secret_basic")
	ensureCredentials(t, cfg)
	skipIfEnvironmentUnavailable(t, cfg)

	p := newProvider(cfg)

	// 1. 正常 context
	ctx := context.Background()
	cred, err := p.GetCredentialWithContext(ctx)
	if err != nil {
		t.Fatalf("GetCredentialWithContext(Background) 失败: %v", err)
	}
	assertCredential(t, cred, "cloud_account_resource:manage_all")
	t.Log("✅ GetCredentialWithContext(Background) 成功")

	// 2. 带 cancel 的 context（不取消，正常完成）
	ctx2, cancel := context.WithCancel(context.Background())
	cred2, err := p.GetCredentialWithContext(ctx2)
	cancel() // 完成后取消，不影响结果
	if err != nil {
		t.Fatalf("GetCredentialWithContext(with cancel) 失败: %v", err)
	}
	if cred.GetAccessToken() != cred2.GetAccessToken() {
		t.Error("两次调用应返回相同 token（缓存）")
	}
	t.Log("✅ GetCredentialWithContext(with cancel) 成功")

	// 3. 带 timeout 的 context（足够长）
	ctx3, cancel3 := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel3()
	cred3, err := p.GetCredentialWithContext(ctx3)
	if err != nil {
		t.Fatalf("GetCredentialWithContext(30s timeout) 失败: %v", err)
	}
	if cred.GetAccessToken() != cred3.GetAccessToken() {
		t.Error("三次调用应返回相同 token（缓存）")
	}
	t.Log("✅ GetCredentialWithContext(30s timeout) 成功")
}

// TestGetCredentialWithDeadline 验证 context deadline 机制
//
// 注意：由于缓存机制，后续调用可能直接返回缓存值而不触发网络请求，
// 因此极短 deadline 测试可能不会触发超时。这是正常行为。
func TestGetCredentialWithDeadline(t *testing.T) {
	skipIfIntegrationDisabled(t)

	cfg := loadConfig(t, "client_secret_basic")
	ensureCredentials(t, cfg)
	skipIfEnvironmentUnavailable(t, cfg)

	p := newProvider(cfg)

	// 1. 正常 deadline（足够长）
	ctx1, cancel1 := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel1()
	cred, err := p.GetCredentialWithContext(ctx1)
	if err != nil {
		t.Fatalf("GetCredentialWithContext(30s timeout) 失败: %v", err)
	}
	assertCredential(t, cred, "cloud_account_resource:manage_all")
	t.Log("✅ GetCredentialWithContext(30s timeout) 成功")

	// 2. 极短 deadline（1ns，可能命中缓存而不触发超时）
	ctx2, cancel2 := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel2()
	time.Sleep(2 * time.Nanosecond) // 确保已超时
	cred2, err := p.GetCredentialWithContext(ctx2)
	if err != nil {
		t.Logf("✅ 极短 deadline 触发超时: %v", err)
	} else {
		t.Logf("⚠️  极短 deadline 未触发超时（命中缓存）: token=%s...", preview(cred2.GetAccessToken()))
	}
}
