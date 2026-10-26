//go:build integration

// 负面路径集成用例——此前全部场景都是 happy path，真实环境的错误分类
// （服务端 OAuth2 标准错误 → SDK 结构化错误）与凭证不泄漏只有 mock 单测背书。
package integration

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cloud-idaas/idaas-go-core-sdk/constants"
	idaaserrors "github.com/cloud-idaas/idaas-go-core-sdk/errors"
)

// TestWrongClientSecretInvalidClient 用一把注入的假 client_secret 打真实 endpoint：
//
//  1. 必须被拒绝，且错误码是 invalid_client（RFC 6749 标准名，SDK 的 OAuth2Error 原样透出）；
//  2. 错误文本与 describeError 摊平结果都不得出现注入的假 secret。
//
// 环境噪音防御：返回 DNS/连接类错误说明 endpoint 不可达，与凭证校验无关，skip 而非 FAIL
// ——与其它用例"不把环境问题当代码问题"的探活思路一致。
func TestWrongClientSecretInvalidClient(t *testing.T) {
	skipIfIntegrationDisabled(t)

	cfg := loadConfig(t, "client_secret_basic")
	ensureCredentials(t, cfg)
	skipIfEnvironmentUnavailable(t, cfg)
	if cfg.AuthnConfiguration.ClientSecretEnvVarName == "" {
		t.Skip("配置未声明 clientSecretEnvVarName，无法构造错误凭证场景")
	}

	// 取票在每次请求时读环境变量（SDK 设计支持凭证轮换无需重建 provider），
	// 因此在 newProvider 之前注入假 secret 即可让真实请求带上错误凭证。
	bogus := fmt.Sprintf("bogus-secret-for-integration-%d", time.Now().UnixNano())
	t.Setenv(cfg.AuthnConfiguration.ClientSecretEnvVarName, bogus)

	_, err := newProvider(cfg).GetCredential()
	if err == nil {
		t.Fatal("错误 client_secret 居然换票成功——服务端未校验凭证，或配置指向的不是真实实例")
	}

	for _, code := range []string{constants.DnsLookupFailed, constants.ConnectTimeOut} {
		if idaaserrors.HasCode(err, code) {
			t.Skipf("endpoint 不可达（%s），无法验证 invalid_client: %v", code, err)
		}
	}

	const invalidClient = "invalid_client"
	if !idaaserrors.HasCode(err, invalidClient) {
		t.Errorf("错误码应含 %s, 实际: %v\n%s", invalidClient, err, describeError(err))
	}

	if strings.Contains(err.Error(), bogus) {
		t.Errorf("error 文本泄漏 client_secret: %s", err.Error())
	}
	if strings.Contains(describeError(err), bogus) {
		t.Errorf("describeError 泄漏 client_secret: %s", describeError(err))
	}
	t.Logf("✅ 错误凭证正确拒绝且未泄漏 secret: %s", describeError(err))
}
