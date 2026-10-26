//go:build integration

// factory 公共入口端到端用例。其余用例都直接构造 implementation.NewIDaaSMachineCredentialProvider，
// 绕过了用户真实入口（factory.Init/GetIDaaSCredentialProvider/Reset/缓存/预热）——本文件补这块。
package integration

import (
	"testing"

	"github.com/cloud-idaas/idaas-go-core-sdk/constants"
	idaaserrors "github.com/cloud-idaas/idaas-go-core-sdk/errors"
	"github.com/cloud-idaas/idaas-go-core-sdk/factory"
)

// TestFactoryPublicApiFlow 从用户视角跑一遍真实链路：
//
//  1. factory.Init(.local/client_secret_basic.json) → 取 provider → 换票 → 断言凭证达标；
//  2. 二次 GetIDaaSCredentialProvider + GetCredential 命中缓存（令牌一致）；
//  3. GetIDaaSTokenExchangeCredentialProvider 在 client_secret_* 配置下创建成功（不发交换请求，
//     交换本身的端到端由 TestTokenExchange 覆盖）；
//  4. Reset 之后回到未初始化态：取 provider 必须报 FactoryNotInit（明确错误，不 panic）。
//
// factory 是进程级单例：用例开头/结尾各 Reset 一次，避免与其它集成用例互相污染
// （包内用例默认串行，无需担心并发访问单例）。
func TestFactoryPublicApiFlow(t *testing.T) {
	skipIfIntegrationDisabled(t)

	// 借用 loadConfig 做"配置存在性 + 可解析"检查（缺失时 skip 并提示复制模板），
	// 但被测链路是 factory.Init 从文件加载，两者指向同一个 .local 文件。
	cfg := loadConfig(t, "client_secret_basic")
	ensureCredentials(t, cfg)
	skipIfEnvironmentUnavailable(t, cfg)
	const cfgPath = "testdata/.local/client_secret_basic.json"

	factory.Reset()
	t.Cleanup(factory.Reset)

	if err := factory.Init(cfgPath); err != nil {
		t.Fatalf("factory.Init(%s) 失败: %v", cfgPath, err)
	}

	p, err := factory.GetIDaaSCredentialProvider()
	if err != nil {
		t.Fatalf("GetIDaaSCredentialProvider 失败: %v", err)
	}
	cred, err := p.GetCredential()
	if err != nil {
		t.Fatalf("factory 链路取 Token 失败: %v\n%s", err, describeError(err))
	}
	assertCredential(t, cred, "cloud_account_resource:manage_all")

	p2, err := factory.GetIDaaSCredentialProvider()
	if err != nil {
		t.Fatalf("第二次 GetIDaaSCredentialProvider 失败: %v", err)
	}
	cred2, err := p2.GetCredential()
	if err != nil {
		t.Fatalf("第二次取 Token 失败: %v", err)
	}
	if cred.GetAccessToken() != cred2.GetAccessToken() {
		t.Error("factory 未复用缓存的 provider/凭证：两次调用令牌不一致")
	}

	if _, err := factory.GetIDaaSTokenExchangeCredentialProvider(); err != nil {
		t.Errorf("client_secret_* 配置下应能创建 token-exchange provider: %v", err)
	}

	factory.Reset()
	if _, err := factory.GetIDaaSCredentialProvider(); !idaaserrors.HasCode(err, constants.IDaaSCredentialProviderFactoryNotInit) {
		t.Errorf("Reset 后应报 %s, 实际: %v", constants.IDaaSCredentialProviderFactoryNotInit, err)
	}
}
