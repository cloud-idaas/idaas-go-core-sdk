//go:build integration

package integration

import (
	"testing"
	"time"
)

// 每个认证方式一个测试函数，可单独运行：
//
//	go test -tags integration -v -run TestClientSecret ./integration/   # 三种 client_secret 变体
//	go test -tags integration -v -run TestPCA ./integration/            # 只跑 PrivateCA
//	go test -tags integration -v -run TestPkcs7 ./integration/          # 只跑 ECS PKCS7（需在 ECS 上）
//	go test -tags integration -v -run TestOidc ./integration/           # 只跑 OIDC 联邦（需 token 文件）
//	go test -tags integration -v -run TestPlugin ./integration/         # 插件认证（进程内注册回声插件）
//	go test -tags integration -v -run TestTokenExchange ./integration/  # RFC 8693 令牌交换
//	go test -tags integration -v -run TestFactoryPublicApiFlow ./integration/ # factory 公共入口

func TestClientSecretBasic(t *testing.T) {
	cred, _ := obtainToken(t, "client_secret_basic")
	assertCredential(t, cred, "cloud_account_resource:manage_all")
}

func TestClientSecretPost(t *testing.T) {
	cred, _ := obtainToken(t, "client_secret_post")
	assertCredential(t, cred, "cloud_account_resource:manage_all")
}

func TestClientSecretJwt(t *testing.T) {
	cred, _ := obtainToken(t, "client_secret_jwt")
	assertCredential(t, cred, "cloud_account_resource:manage_all")
}

func TestPrivateKeyJwt(t *testing.T) {
	cred, _ := obtainToken(t, "private_key_jwt")
	assertCredential(t, cred, "cloud_account_resource:manage_all")
}

func TestPCA(t *testing.T) {
	cred, _ := obtainToken(t, "pca")
	assertCredential(t, cred, "cloud_account_resource:manage_all")
}

// TestPkcs7 走 ECS 实例身份（IMDSv2 取 PKCS7 attested document）的 M2M 换票链路。
// 元数据服务地址在 SDK 里是硬编码的 100.100.100.200，因此只有在真实阿里云 ECS 实例上
// 才跑得起来；开发机上会因探活失败而 skip。
func TestPkcs7(t *testing.T) {
	cred, _ := obtainToken(t, "pkcs7")
	assertCredential(t, cred, "cloud_account_resource:manage_all")
}

// TestOidc 走 OIDC 联邦凭证（clientDeployEnvironment=COMPUTER，本地开发模式）换 M2M Token。
//
// 与 KUBERNETES 的区别：COMPUTER 不回落到 K8s SA 默认路径，必须显式给出 token 文件——
// 由 authnConfiguration.oidcTokenFilePath 或其指向的环境变量（此处 OIDC_TOKEN_FILE_PATH）提供。
// 该文件里应是 IDaaS 侧 ql_oidc_test 联邦凭证所信任的 issuer 签发的 ID Token（JWT）。
func TestOidc(t *testing.T) {
	cred, _ := obtainToken(t, "oidc_computer")
	assertCredential(t, cred, "cloud_account_resource:manage_all")
}

// TestAllAuthnMethods 按 testdata 里的配置逐个跑一遍，最后给出通过/失败汇总。
// 单个方式失败不会中断其余方式，便于一次看清整组兼容性。
//
// 注意不含 plugin：插件实现必须由测试进程注册（见 TestPluginAuthn），不是纯配置驱动的链路。
func TestAllAuthnMethods(t *testing.T) {
	skipIfIntegrationDisabled(t)

	cases := []string{
		"client_secret_basic",
		"client_secret_post",
		"client_secret_jwt",
		"private_key_jwt",
		"pca",
		"pkcs7",
		"pkcs7_aws_ec2",
		"oidc_computer",
		"oidc_kubernetes",
		"oidc_azure_vm",
		"oidc_google_vm",
	}
	loadLocalEnv(t)

	for _, name := range cases {
		name := name
		t.Run(name, func(t *testing.T) {
			cfg := loadConfig(t, name)
			ensureCredentials(t, cfg)
			skipIfEnvironmentUnavailable(t, cfg)
			cred, err := newProvider(cfg).GetCredential()
			if err != nil {
				t.Errorf("authnMethod=%s 获取 Token 失败: %v\n%s", cfg.AuthnConfiguration.AuthnMethod, err, describeError(err))
				return
			}
			assertCredential(t, cred, "")
		})
	}
}

// TestCachedCredentialIsReused 验证同一 provider 第二次取凭证命中缓存：
// 令牌完全一致，且第二次调用明显快于首次的真实请求。
func TestCachedCredentialIsReused(t *testing.T) {
	skipIfIntegrationDisabled(t)

	cfg := loadConfig(t, "client_secret_basic")
	ensureCredentials(t, cfg)
	p := newProvider(cfg)

	first, err := p.GetCredential()
	if err != nil {
		t.Fatalf("首次获取失败: %v", err)
	}

	started := time.Now()
	second, err := p.GetCredential()
	elapsed := time.Since(started)
	if err != nil {
		t.Fatalf("第二次获取失败: %v", err)
	}

	if first.GetAccessToken() != second.GetAccessToken() {
		t.Errorf("第二次未命中缓存：令牌发生变化")
	}
	if elapsed > time.Second {
		t.Errorf("第二次耗时 %v 偏长，疑似重新发起了 HTTP 请求", elapsed)
	}
	t.Logf("✅ 缓存命中，第二次耗时 %v", elapsed.Round(time.Millisecond))
}
