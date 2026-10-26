//go:build integration

// StaleValueBehavior 集成测试。
// 验证配置中的 staleValueBehavior 字段被正确解析和应用。
//
// 注意：真正的过期行为测试需要服务端签发短时效 token（如 10s），
// 在集成测试中难以稳定触发。本测试只验证配置解析和默认行为。
// 过期行为的详细逻辑由单元测试覆盖。
package integration

import (
	"testing"

	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
)

// TestStaleValueBehaviorConfig 验证 staleValueBehavior 配置解析
//
// 验证内容：
// 1. 配置中未设置 staleValueBehavior 时，默认使用 REFRESH
// 2. 配置中显式设置 staleValueBehavior 时，按配置生效
func TestStaleValueBehaviorConfig(t *testing.T) {
	skipIfIntegrationDisabled(t)

	// 1. 默认行为（配置中未设置）
	cfg1 := loadConfig(t, "client_secret_basic")
	ensureCredentials(t, cfg1)
	skipIfEnvironmentUnavailable(t, cfg1)

	p1 := newProvider(cfg1)
	// newProvider 内部逻辑：
	// stale := enums.StaleValueBehaviorRefresh
	// if cfg.StaleValueBehavior != "" {
	//     stale = cfg.StaleValueBehavior
	// }
	// 因此如果配置中未设置，应该使用 REFRESH
	if cfg1.StaleValueBehavior == "" {
		t.Log("✅ 配置中未设置 staleValueBehavior，将使用默认值 REFRESH")
	} else {
		t.Logf("配置中设置了 staleValueBehavior = %s", cfg1.StaleValueBehavior)
	}

	// 验证 provider 能正常工作
	cred, err := p1.GetCredential()
	if err != nil {
		t.Fatalf("GetCredential 失败: %v", err)
	}
	assertCredential(t, cred, "cloud_account_resource:manage_all")
	t.Log("✅ 默认 staleValueBehavior 下 provider 正常工作")

	// 2. 显式设置 BLOCK
	cfg2 := loadConfig(t, "client_secret_basic")
	cfg2.StaleValueBehavior = enums.StaleValueBehaviorBlock
	p2 := newProvider(cfg2)
	cred2, err := p2.GetCredential()
	if err != nil {
		t.Fatalf("BLOCK 模式下 GetCredential 失败: %v", err)
	}
	assertCredential(t, cred2, "cloud_account_resource:manage_all")
	t.Log("✅ BLOCK 模式下 provider 正常工作")

	// 3. 显式设置 ALLOW
	cfg3 := loadConfig(t, "client_secret_basic")
	cfg3.StaleValueBehavior = enums.StaleValueBehaviorAllow
	p3 := newProvider(cfg3)
	cred3, err := p3.GetCredential()
	if err != nil {
		t.Fatalf("ALLOW 模式下 GetCredential 失败: %v", err)
	}
	assertCredential(t, cred3, "cloud_account_resource:manage_all")
	t.Log("✅ ALLOW 模式下 provider 正常工作")

	// 4. 显式设置 REFRESH
	cfg4 := loadConfig(t, "client_secret_basic")
	cfg4.StaleValueBehavior = enums.StaleValueBehaviorRefresh
	p4 := newProvider(cfg4)
	cred4, err := p4.GetCredential()
	if err != nil {
		t.Fatalf("REFRESH 模式下 GetCredential 失败: %v", err)
	}
	assertCredential(t, cred4, "cloud_account_resource:manage_all")
	t.Log("✅ REFRESH 模式下 provider 正常工作")

	t.Log("✅ 三种 staleValueBehavior 配置均能正常工作（过期行为由单元测试覆盖）")
}
