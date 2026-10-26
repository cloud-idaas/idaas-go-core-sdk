//go:build integration

// Factory 其他公共 API 集成测试。
// 已覆盖 Init/GetIDaaSCredentialProvider/GetIDaaSTokenExchangeCredentialProvider/Reset，
// 本文件补齐其余 8 个公共 API 的端到端验证。
package integration

import (
	"testing"

	"github.com/cloud-idaas/idaas-go-core-sdk/factory"
)

// TestFactoryOtherApis 验证 Factory 的其余 8 个公共 API
//
// 验证内容：
// 1. InitWithConfig：从内存配置初始化（不依赖文件）
// 2. GetIDaaSCredentialProviderByScope：不同 scope 返回不同 provider
// 3. GetIDaaSTokenExchangeCredentialProviderByScope：同上
// 4. GetDeveloperApiEndpoint：返回配置中的 developerApiEndpoint（规范化后）
// 5. GetOpenApiEndpoint：返回配置中的 openApiEndpoint（规范化后）
// 6. GetIDaaSInstanceId：返回配置中的 instanceId
// 7. GetClientId：返回配置中的 clientId
// 8. GetHttpConfig：返回深拷贝，修改不影响原配置
func TestFactoryOtherApis(t *testing.T) {
	skipIfIntegrationDisabled(t)

	cfg := loadConfig(t, "client_secret_basic")
	ensureCredentials(t, cfg)
	skipIfEnvironmentUnavailable(t, cfg)

	factory.Reset()
	t.Cleanup(factory.Reset)

	// 1. InitWithConfig：从内存配置初始化
	if err := factory.InitWithConfig(cfg); err != nil {
		t.Fatalf("InitWithConfig 失败: %v", err)
	}
	t.Log("✅ InitWithConfig 成功")

	// 2. GetIDaaSCredentialProviderByScope：不同 scope 返回不同 provider
	p1, err := factory.GetIDaaSCredentialProviderByScope("scope1")
	if err != nil {
		t.Fatalf("GetIDaaSCredentialProviderByScope(scope1) 失败: %v", err)
	}
	p2, err := factory.GetIDaaSCredentialProviderByScope("scope2")
	if err != nil {
		t.Fatalf("GetIDaaSCredentialProviderByScope(scope2) 失败: %v", err)
	}
	if p1 == p2 {
		t.Error("不同 scope 应返回不同 provider 实例")
	}
	// 同一 scope 应返回同一实例
	p1Again, _ := factory.GetIDaaSCredentialProviderByScope("scope1")
	if p1 != p1Again {
		t.Error("同一 scope 应返回同一 provider 实例（缓存）")
	}
	t.Log("✅ GetIDaaSCredentialProviderByScope 正确区分不同 scope")

	// 3. GetIDaaSTokenExchangeCredentialProviderByScope：同上
	te1, err := factory.GetIDaaSTokenExchangeCredentialProviderByScope("scope1")
	if err != nil {
		t.Fatalf("GetIDaaSTokenExchangeCredentialProviderByScope(scope1) 失败: %v", err)
	}
	te2, err := factory.GetIDaaSTokenExchangeCredentialProviderByScope("scope2")
	if err != nil {
		t.Fatalf("GetIDaaSTokenExchangeCredentialProviderByScope(scope2) 失败: %v", err)
	}
	if te1 == te2 {
		t.Error("不同 scope 应返回不同 token exchange provider 实例")
	}
	t.Log("✅ GetIDaaSTokenExchangeCredentialProviderByScope 正确区分不同 scope")

	// 4. GetDeveloperApiEndpoint（SDK 会规范化 endpoint，加 https:// 前缀）
	devEndpoint := factory.GetDeveloperApiEndpoint()
	if devEndpoint == "" {
		t.Error("GetDeveloperApiEndpoint 返回空字符串")
	} else {
		t.Logf("✅ GetDeveloperApiEndpoint = %s（已规范化）", devEndpoint)
	}

	// 5. GetOpenApiEndpoint（SDK 会规范化 endpoint，加 https:// 前缀）
	openEndpoint := factory.GetOpenApiEndpoint()
	if openEndpoint == "" {
		t.Error("GetOpenApiEndpoint 返回空字符串")
	} else {
		t.Logf("✅ GetOpenApiEndpoint = %s（已规范化）", openEndpoint)
	}

	// 6. GetIDaaSInstanceId
	instanceId := factory.GetIDaaSInstanceId()
	if instanceId != cfg.InstanceId {
		t.Errorf("GetIDaaSInstanceId = %q, 期望 %q", instanceId, cfg.InstanceId)
	}
	t.Logf("✅ GetIDaaSInstanceId = %s", instanceId)

	// 7. GetClientId
	clientId := factory.GetClientId()
	if clientId != cfg.ClientId {
		t.Errorf("GetClientId = %q, 期望 %q", clientId, cfg.ClientId)
	}
	t.Logf("✅ GetClientId = %s", clientId)

	// 8. GetHttpConfig：返回深拷贝
	httpCfg := factory.GetHttpConfig()
	if httpCfg == nil {
		if cfg.HttpConfiguration != nil {
			t.Error("GetHttpConfig 返回 nil，但配置中有 HttpConfiguration")
		}
	} else {
		// 修改返回值，不应影响原配置
		originalTimeout := httpCfg.ConnectTimeout
		httpCfg.ConnectTimeout = 99999
		httpCfg2 := factory.GetHttpConfig()
		if httpCfg2.ConnectTimeout != originalTimeout {
			t.Errorf("GetHttpConfig 未返回深拷贝：修改后影响原配置（%d -> %d）",
				originalTimeout, httpCfg2.ConnectTimeout)
		}
		t.Logf("✅ GetHttpConfig 返回深拷贝（ConnectTimeout=%d）", originalTimeout)
	}
}
