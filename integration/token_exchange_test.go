//go:build integration

// RFC 8693 Token Exchange 端到端用例（machine_token_exchange_provider）。
// 此前该能力只有 samples/token-exchange 手工链路，集成层零覆盖。
package integration

import (
	"os"
	"strings"
	"testing"

	"github.com/cloud-idaas/idaas-go-core-sdk/internal/implementation"
	"github.com/cloud-idaas/idaas-go-core-sdk/provider"
)

// TestTokenExchange 端到端步骤：
//
//  1. 用 client_secret_post 链路先拿到一张真实 IDaaS Access Token 作 subject_token
//     （samples 用 IDAAS_SUBJECT_TOKEN 环境变量注入，这里自给自足以便自动化）；
//  2. 构造 exchange provider，用 provider 绑定的 scope 发起交换；
//  3. 断言返回可用的 Bearer token；
//  4. 负面分支：空 subject_token 必须被拒绝（SDK 客户端报错或服务端 OAuth2 报错都算通过）。
//
// 前置条件：实例/应用需开通 token-exchange grant；未开通时服务端返回 OAuth2 错误、用例 FAIL，
// 这正是集成测试要暴露的真实配置问题（describeError 会带上 requestId 便于服务端排查）。
func TestTokenExchange(t *testing.T) {
	skipIfIntegrationDisabled(t)

	cfg := loadConfig(t, "client_secret_post")
	ensureCredentials(t, cfg)
	skipIfEnvironmentUnavailable(t, cfg)

	// subject_token_type：默认 urn:ietf:params:oauth:token-type:access_token；
	// 注入用户态 ID Token 作 subject 时通常需设为 ...token-type:id_token（IDAAS_SUBJECT_TOKEN_TYPE）。
	subjectTokenType := strings.TrimSpace(os.Getenv("IDAAS_SUBJECT_TOKEN_TYPE"))

	// subject token 来源优先级：IDAAS_SUBJECT_TOKEN（人工注入的用户态/特定签发方 token）
	// → client_secret_post 自产 M2M token 兜底。部分实例只接受用户态 token 作 subject，
	// 自产 M2M token 会被拒（invalid_grant），此时用注入方式复测。
	subjectToken := strings.TrimSpace(os.Getenv("IDAAS_SUBJECT_TOKEN"))
	if subjectToken != "" {
		t.Logf("subject_token 来源: IDAAS_SUBJECT_TOKEN 注入（跳过 M2M 自产），subject_token_type=%s（空=默认 access_token）",
			orDefault(subjectTokenType, "urn:ietf:params:oauth:token-type:access_token"))
	} else {
		subjectCred, err := newProvider(cfg).GetCredential()
		if err != nil {
			t.Fatalf("获取 subject token 失败（client_secret_post 链路；可用 IDAAS_SUBJECT_TOKEN 切换来源）: %v\n%s", err, describeError(err))
		}
		subjectToken = subjectCred.GetAccessToken()
		t.Log("subject_token 来源: client_secret_post 自产 M2M token")
	}

	// target scope：IDAAS_EXCHANGE_SCOPE 未设时沿用 provider 绑定的配置 scope
	targetScope := strings.TrimSpace(os.Getenv("IDAAS_EXCHANGE_SCOPE"))
	if targetScope != "" {
		t.Logf("target scope 覆盖: IDAAS_EXCHANGE_SCOPE=%s", targetScope)
	}

	exchange := implementation.NewIDaaSMachineTokenExchangeCredentialProvider(cfg, cfg.Scope, newHttpClientFromConfig(cfg))
	cred, err := exchange.ExchangeToken(provider.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: subjectTokenType,
		Scope:            targetScope,
	})
	if err != nil {
		t.Fatalf("RFC 8693 token exchange 失败（确认实例已开通 token-exchange）: %v\n%s", err, describeError(err))
	}
	assertCredential(t, cred, "")

	if cred.GetAccessToken() == subjectToken {
		t.Log("注意：换出的 token 与 subject token 相同，请核对服务端是否为直通语义")
	}

	t.Run("missing_subject_token", func(t *testing.T) {
		if _, err := exchange.ExchangeToken(provider.TokenExchangeRequest{}); err == nil {
			t.Fatal("空 subject_token 应被拒绝（RFC 8693 必填），服务端/SDK 均未报错")
		} else {
			t.Logf("✅ 空 subject_token 正确拒绝: %s", describeError(err))
		}
	})
}

// orDefault 日志辅助：空值显示默认文案。
func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
