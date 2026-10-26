//go:build integration

// 本文件补齐第 8 种 M2M 认证方式 `plugin` 的集成用例——obtain_token_test.go 覆盖其余 7 种，
// plugin 曾是能力面矩阵里唯一整块缺失的一格。
package integration

import (
	"sync"
	"testing"

	"github.com/cloud-idaas/idaas-go-core-sdk/constants"
	"github.com/cloud-idaas/idaas-go-core-sdk/credential"
	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
	idaaserrors "github.com/cloud-idaas/idaas-go-core-sdk/errors"
	"github.com/cloud-idaas/idaas-go-core-sdk/plugin"
	"github.com/cloud-idaas/idaas-go-core-sdk/provider"
)

// integrationEchoPluginName 是回声插件的注册名，也是 testdata/plugin.example.json 里的 pluginName。
const integrationEchoPluginName = "integration_echo"

// echoPlugin 是集成测试用的回声插件：把取票委托给真实的 client_secret 链路。
//
// PluginCredentialProvider 的契约是"插件自行获取完整 token，SDK 不发起 HTTP 请求"。
// 为了在没有外部系统（如阿里云 EIAM OpenAPI）依赖的前提下做真端到端，
// 本插件内部接 SDK 的真实 IdP client_secret 链路：token 是从真实 IdP 换来的，
// 用例验证的重点是 plugin 装配链路（注册→查找→scope 透传→凭证回传），而非签名算法。
type echoPlugin struct {
	inner provider.IDaaSCredentialProvider

	mu        sync.Mutex
	lastScope string
}

func (p *echoPlugin) GetName() string { return integrationEchoPluginName }

func (p *echoPlugin) GetIDaaSCredential(scope string) (credential.IDaaSCredential, error) {
	p.mu.Lock()
	p.lastScope = scope
	p.mu.Unlock()
	// inner 在构造时绑定 cfg.Scope；若外层/内层 scope 不一致，可在用例子断言里看到差异
	return p.inner.GetCredential()
}

func (p *echoPlugin) takenScope() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastScope
}

// TestPluginAuthn 端到端验证 authnMethod=plugin 走真实链路：
//
//  1. 把持有真实 client_secret 链路的 echoPlugin 注册进进程级 plugin.GetInstance()；
//  2. 用 client_secret_basic 配置的副本改为 authnMethod=PLUGIN + pluginName，
//     走完整 machine provider → getPluginCredential → registry → 插件 → 真实 IdP 换票；
//  3. 断言返回凭证达标，且插件收到的 scope 与配置一致；
//  4. 负面分支：未注册 pluginName → PluginNotFound；空 pluginName → PluginNameNotFound。
//
// 前置条件同 TestClientSecretBasic（.local/client_secret_basic.json + IDAAS_CLIENT_SECRET）。
// 插件注册是进程内行为，因此 plugin 不在 TestAllAuthnMethods 的纯配置驱动枚举之列。
func TestPluginAuthn(t *testing.T) {
	skipIfIntegrationDisabled(t)

	cfg := loadConfig(t, "client_secret_basic")
	ensureCredentials(t, cfg)
	skipIfEnvironmentUnavailable(t, cfg)

	reg := plugin.GetInstance()
	// 单例在同一进程多次跑/多用例共享时可能有残留：先清再注册，保证 inner 指向当前环境凭证
	_ = reg.Unregister(integrationEchoPluginName)
	p := &echoPlugin{inner: newProvider(cfg)}
	if err := reg.Register(p); err != nil {
		t.Fatalf("插件注册失败: %v", err)
	}
	t.Cleanup(func() { _ = reg.Unregister(integrationEchoPluginName) })

	// 复制一份配置改为 plugin 认证（原 cfg 不动——inner 的 provider 还在用它）
	pluginCfg := *cfg
	authn := *cfg.AuthnConfiguration
	authn.AuthnMethod = enums.TokenAuthnMethodPlugin
	authn.PluginName = integrationEchoPluginName
	pluginCfg.AuthnConfiguration = &authn

	cred, err := newProvider(&pluginCfg).GetCredential()
	if err != nil {
		t.Fatalf("authnMethod=plugin 获取 Token 失败: %v\n%s", err, describeError(err))
	}
	assertCredential(t, cred, "cloud_account_resource:manage_all")

	if got := p.takenScope(); got != cfg.Scope {
		t.Errorf("插件收到的 scope=%q, 与配置 scope=%q 不一致", got, cfg.Scope)
	}

	t.Run("unknown_plugin", func(t *testing.T) {
		bad := pluginCfg
		badAuthn := *pluginCfg.AuthnConfiguration
		badAuthn.PluginName = integrationEchoPluginName + "_not_registered"
		bad.AuthnConfiguration = &badAuthn

		_, err := newProvider(&bad).GetCredential()
		if err == nil {
			t.Fatal("用未注册的插件取凭证应当失败")
		}
		if !idaaserrors.HasCode(err, constants.PluginNotFound) {
			t.Errorf("错误码应为 %s: %v\n%s", constants.PluginNotFound, err, describeError(err))
		}
	})

	t.Run("empty_plugin_name", func(t *testing.T) {
		bad := pluginCfg
		badAuthn := *pluginCfg.AuthnConfiguration
		badAuthn.PluginName = ""
		bad.AuthnConfiguration = &badAuthn

		_, err := newProvider(&bad).GetCredential()
		if err == nil {
			t.Fatal("pluginName 为空取凭证应当失败")
		}
		if !idaaserrors.HasCode(err, constants.PluginNameNotFound) {
			t.Errorf("错误码应为 %s: %v\n%s", constants.PluginNameNotFound, err, describeError(err))
		}
	})
}
