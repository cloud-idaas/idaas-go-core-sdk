package config

import (
	"os"
	"testing"

	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
)

// TestConfigReaderLoadFromEnv_ClientSecretJwt 验证 LoadFromEnv 对
// client_secret_jwt 认证方式应设置 ClientSecretEnvVarName(指向 CLOUD_IDAAS_CLIENT_SECRET)。
//
// client_secret_jwt 与 client_secret_basic / client_secret_post 一样需要
// client_secret 来构造 JWT 断言,故三者共用同一 env var 注入路径,
// 缺少则宿主无法通过环境变量提供密钥。
func TestConfigReaderLoadFromEnv_ClientSecretJwt(t *testing.T) {
	os.Setenv("CLOUD_IDAAS_CLIENT_ID", "test_client")
	os.Setenv("CLOUD_IDAAS_INSTANCE_ID", "test_instance")
	os.Setenv("CLOUD_IDAAS_ISSUER_ENDPOINT", "https://test.example.com/oauth2")
	os.Setenv("CLOUD_IDAAS_TOKEN_ENDPOINT", "https://test.example.com/oauth2/token")
	os.Setenv("CLOUD_IDAAS_SCOPE", "api.example.com|read")
	os.Setenv("CLOUD_IDAAS_AUTHN_METHOD", "client_secret_jwt")
	os.Setenv("CLOUD_IDAAS_CLIENT_SECRET", "test_secret")

	defer func() {
		os.Unsetenv("CLOUD_IDAAS_CLIENT_ID")
		os.Unsetenv("CLOUD_IDAAS_INSTANCE_ID")
		os.Unsetenv("CLOUD_IDAAS_ISSUER_ENDPOINT")
		os.Unsetenv("CLOUD_IDAAS_TOKEN_ENDPOINT")
		os.Unsetenv("CLOUD_IDAAS_SCOPE")
		os.Unsetenv("CLOUD_IDAAS_AUTHN_METHOD")
		os.Unsetenv("CLOUD_IDAAS_CLIENT_SECRET")
	}()

	reader := NewConfigReader()
	cfg, err := reader.LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv failed for client_secret_jwt: %v", err)
	}

	if cfg.AuthnConfiguration == nil {
		t.Fatal("Expected AuthnConfiguration to not be nil")
	}
	if cfg.AuthnConfiguration.AuthnMethod != enums.TokenAuthnMethodClientSecretJwt {
		t.Errorf("Expected AuthnMethod client_secret_jwt, got %s",
			cfg.AuthnConfiguration.AuthnMethod)
	}
	// client_secret_jwt 与 basic/post 共用 client_secret env var。
	if cfg.AuthnConfiguration.ClientSecretEnvVarName != "CLOUD_IDAAS_CLIENT_SECRET" {
		t.Errorf("expected ClientSecretEnvVarName 'CLOUD_IDAAS_CLIENT_SECRET' for client_secret_jwt, got %s",
			cfg.AuthnConfiguration.ClientSecretEnvVarName)
	}
}
