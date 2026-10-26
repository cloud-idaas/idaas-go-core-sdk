//go:build integration

// refresh_token 续期链路端到端用例。此前只有 samples/refresh-token 手工覆盖；
// M2M client_credentials 不下发 refresh_token，无法全自动化，故设计为
// "拿到真实 refresh_token 后可一键复测"的半自动入口。
package integration

import (
	"os"
	"testing"

	"github.com/cloud-idaas/idaas-go-core-sdk/oauth2"
)

// TestRefreshTokenRenewal 用既有 refresh_token 向真实 endpoint 续期：
//
//  1. refresh_token 来源：环境变量 IDAAS_REFRESH_TOKEN
//     （通常由 device code / human 流程先前签发的响应中取得）；未设置则 skip；
//  2. 走与 sample 相同的公共 API oauth2.OAuth2TokenUtil.RefreshToken；
//  3. 断言换回新的可用 Bearer token。
//
// 说明：RefreshToken 公共方法仅带 client_id（public client 形态），与 sample 一致；
// 若实例要求 confidential client 携带凭证续期而服务端报 invalid_client，属于
// 该 API 形态与环境要求的差异，日志会保留 requestId 便于服务端定位。
func TestRefreshTokenRenewal(t *testing.T) {
	skipIfIntegrationDisabled(t)

	cfg := loadConfig(t, "client_secret_basic")
	ensureCredentials(t, cfg)
	skipIfEnvironmentUnavailable(t, cfg)

	refreshToken := os.Getenv("IDAAS_REFRESH_TOKEN")
	if refreshToken == "" {
		t.Skip("需要 IDAAS_REFRESH_TOKEN：请先通过 device code/human 流程取得 refresh_token 再复测本用例")
	}

	resp, err := oauth2.NewOAuth2TokenUtil(newHttpClientFromConfig(cfg)).
		RefreshToken(cfg.TokenEndpoint, cfg.ClientId, refreshToken)
	if err != nil {
		t.Fatalf("refresh_token 续期失败: %v\n%s", err, describeError(err))
	}
	assertCredential(t, resp, "")
	t.Logf("✅ refresh_token 续期成功（服务端可能轮换 refresh_token：%v）",
		resp.GetRefreshToken() != "" && resp.GetRefreshToken() != refreshToken)
}
