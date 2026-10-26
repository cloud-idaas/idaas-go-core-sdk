package implementation

import (
	"context"
	"strings"
	"testing"

	"github.com/cloud-idaas/idaas-go-core-sdk/config"
	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
)

// secretEnv 是本测试使用的私有 env var 名,避免与全局 CLOUD_IDAAS_CLIENT_SECRET 冲突。
const testSecretEnv = "GO_SDK_TEST_CLIENT_SECRET"

func setTestSecret(t *testing.T, val string) {
	t.Helper()
	t.Setenv(testSecretEnv, val)
}

// newAuthnCfg 构造一个填好 ClientSecretEnvVarName 的认证配置。
func newAuthnCfg(method enums.TokenAuthnMethod) *config.IdentityAuthenticationConfiguration {
	return &config.IdentityAuthenticationConfiguration{
		AuthnMethod:            method,
		ClientSecretEnvVarName: testSecretEnv,
	}
}

// TestBuildClientAuthentication_NilAuthnConf 覆盖 authnConf==nil 分支。
func TestBuildClientAuthentication_NilAuthnConf(t *testing.T) {
	cfg := &config.IDaaSClientConfig{ClientId: "cid"}
	_, err := buildClientAuthentication(context.Background(), cfg, nil)
	if err == nil {
		t.Fatal("expected error when AuthnConfiguration is nil")
	}
}

// TestBuildClientAuthentication_ClientSecretBasic 覆盖 client_secret_basic 分支:
// 验证 Authorization Basic 头被设置且包含 base64 编码的 id:secret。
func TestBuildClientAuthentication_ClientSecretBasic(t *testing.T) {
	setTestSecret(t, "topsecret")
	cfg := &config.IDaaSClientConfig{
		ClientId:           "client-1",
		TokenEndpoint:      "https://example.test/token",
		AuthnConfiguration: newAuthnCfg(enums.TokenAuthnMethodClientSecretBasic),
	}
	auth, err := buildClientAuthentication(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if auth.Headers == nil {
		t.Fatal("expected Authorization header for client_secret_basic")
	}
	v, ok := auth.Headers["Authorization"]
	if !ok || !strings.HasPrefix(v, "Basic ") {
		t.Errorf("expected 'Basic <b64>' header, got %q", v)
	}
	if v := auth.Form.Get("client_id"); v != "client-1" {
		t.Errorf("expected client_id in form, got %q", v)
	}
}

// TestBuildClientAuthentication_ClientSecretBasic_MissingSecret 覆盖 basic 读取密钥失败分支。
func TestBuildClientAuthentication_ClientSecretBasic_MissingSecret(t *testing.T) {
	// 不设置 secret env(默认空)
	cfg := &config.IDaaSClientConfig{
		ClientId:           "client-1",
		TokenEndpoint:      "https://example.test/token",
		AuthnConfiguration: newAuthnCfg(enums.TokenAuthnMethodClientSecretBasic),
	}
	_, err := buildClientAuthentication(context.Background(), cfg, nil)
	if err == nil {
		t.Fatal("expected error when client secret is missing for basic")
	}
}

// TestBuildClientAuthentication_ClientSecretPost 覆盖 client_secret_post 分支:
// 密钥进 form 而非 header。
func TestBuildClientAuthentication_ClientSecretPost(t *testing.T) {
	setTestSecret(t, "postsecret")
	cfg := &config.IDaaSClientConfig{
		ClientId:           "client-2",
		TokenEndpoint:      "https://example.test/token",
		AuthnConfiguration: newAuthnCfg(enums.TokenAuthnMethodClientSecretPost),
	}
	auth, err := buildClientAuthentication(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if auth.Headers != nil {
		t.Errorf("post method should not set headers, got %v", auth.Headers)
	}
	if v := auth.Form.Get("client_secret"); v != "postsecret" {
		t.Errorf("expected client_secret in form, got %q", v)
	}
}

// TestBuildClientAuthentication_ClientSecretJwt 覆盖 client_secret_jwt 分支:
// 用密钥 HS256 签发 JWT 断言,设置 client_assertion / client_assertion_type。
func TestBuildClientAuthentication_ClientSecretJwt(t *testing.T) {
	setTestSecret(t, "jwtsecret")
	cfg := &config.IDaaSClientConfig{
		ClientId:           "client-3",
		TokenEndpoint:      "https://example.test/token",
		AuthnConfiguration: newAuthnCfg(enums.TokenAuthnMethodClientSecretJwt),
	}
	auth, err := buildClientAuthentication(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a := auth.Form.Get("client_assertion"); a == "" {
		t.Error("expected non-empty client_assertion for client_secret_jwt")
	}
	if at := auth.Form.Get("client_assertion_type"); at == "" {
		t.Error("expected non-empty client_assertion_type for client_secret_jwt")
	}
}

// TestBuildClientAuthentication_UnsupportedMethod 覆盖 default 分支:
// 未知 authn method 返回 client error。
func TestBuildClientAuthentication_UnsupportedMethod(t *testing.T) {
	cfg := &config.IDaaSClientConfig{
		ClientId:      "client-x",
		TokenEndpoint: "https://example.test/token",
		AuthnConfiguration: &config.IdentityAuthenticationConfiguration{
			AuthnMethod: enums.TokenAuthnMethod("bogus_method"),
		},
	}
	_, err := buildClientAuthentication(context.Background(), cfg, nil)
	if err == nil {
		t.Fatal("expected error for unsupported authn method")
	}
}

// TestBuildClientAuthentication_PrivateKeyJwt_MissingEnvName 覆盖 private_key_jwt
// 但 PrivateKeyEnvVarName 为空 → loadClientAuthentication 失败分支。
func TestBuildClientAuthentication_PrivateKeyJwt_MissingEnvName(t *testing.T) {
	cfg := &config.IDaaSClientConfig{
		ClientId:      "client-4",
		TokenEndpoint: "https://example.test/token",
		AuthnConfiguration: &config.IdentityAuthenticationConfiguration{
			AuthnMethod: enums.TokenAuthnMethodPrivateKeyJwt,
			// PrivateKeyEnvVarName 留空
		},
	}
	_, err := buildClientAuthentication(context.Background(), cfg, nil)
	if err == nil {
		t.Fatal("expected error when PrivateKeyEnvVarName is empty for private_key_jwt")
	}
}

// TestBuildClientAuthentication_PCA_MissingCert 覆盖 pca 分支:
// ClientX509Certificate 为空 → 提前返回 config error。
func TestBuildClientAuthentication_PCA_MissingCert(t *testing.T) {
	cfg := &config.IDaaSClientConfig{
		ClientId:      "client-5",
		TokenEndpoint: "https://example.test/token",
		AuthnConfiguration: &config.IdentityAuthenticationConfiguration{
			AuthnMethod: enums.TokenAuthnMethodPca,
			// ClientX509Certificate 留空
		},
	}
	_, err := buildClientAuthentication(context.Background(), cfg, nil)
	if err == nil {
		t.Fatal("expected error when ClientX509Certificate is empty for pca")
	}
}
