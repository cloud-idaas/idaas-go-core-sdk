package factory

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cloud-idaas/idaas-go-core-sdk/config"
)

// TestBoundaryInitialize_NilConfig 验证 Initialize 传入 nil config 时返回非 nil error
func TestBoundaryInitialize_NilConfig(t *testing.T) {
	Reset()
	defer Reset()

	f := GetInstance()
	err := f.Initialize(nil)
	if err == nil {
		t.Fatal("expected error when Initialize receives nil config")
	}
}

// TestBoundaryInitialize_ValidateFails 验证配置缺少 ClientId 时 Validate 失败返回错误
func TestBoundaryInitialize_ValidateFails(t *testing.T) {
	Reset()
	defer Reset()

	// Construct a config missing ClientId
	cfg := validTestConfig()
	cfg.ClientId = ""

	f := GetInstance()
	err := f.Initialize(cfg)
	if err == nil {
		t.Fatal("expected error when config has empty ClientId (Validate failure)")
	}
}

// TestBoundaryInitialize_UnsafeIgnoreSSLCert 验证 UnsafeIgnoreSSLCert=true 时不 panic 且初始化成功
func TestBoundaryInitialize_UnsafeIgnoreSSLCert(t *testing.T) {
	Reset()
	defer Reset()

	os.Setenv("CLOUD_IDAAS_CLIENT_SECRET", "test_secret")
	defer os.Unsetenv("CLOUD_IDAAS_CLIENT_SECRET")

	cfg := validTestConfig()
	cfg.HttpConfiguration = &config.HttpConfiguration{
		ConnectTimeout:      5000,
		ReadTimeout:         10000,
		UnsafeIgnoreSSLCert: true,
	}

	f := GetInstance()
	err := f.Initialize(cfg)
	if err != nil {
		t.Fatalf("Initialize should succeed with UnsafeIgnoreSSLCert=true, got: %v", err)
	}
	if !f.IsInitialized() {
		t.Error("factory should be initialized after Initialize with UnsafeIgnoreSSLCert=true")
	}
}

// TestBoundaryInitialize_AllowInsecureEndpoint 验证 AllowInsecureEndpoint=true 时不 panic 且初始化成功
func TestBoundaryInitialize_AllowInsecureEndpoint(t *testing.T) {
	Reset()
	defer Reset()

	os.Setenv("CLOUD_IDAAS_CLIENT_SECRET", "test_secret")
	defer os.Unsetenv("CLOUD_IDAAS_CLIENT_SECRET")

	cfg := validTestConfig()
	cfg.AllowInsecureEndpoint = true

	f := GetInstance()
	err := f.Initialize(cfg)
	if err != nil {
		t.Fatalf("Initialize should succeed with AllowInsecureEndpoint=true, got: %v", err)
	}
	if !f.IsInitialized() {
		t.Error("factory should be initialized after Initialize with AllowInsecureEndpoint=true")
	}
}

// TestBoundaryGetMethods_ConfigNil 验证未初始化的 factory 实例的 Get* 方法返回零值
func TestBoundaryGetMethods_ConfigNil(t *testing.T) {
	// Create a fresh, uninitialized factory instance (no Initialize call)
	f := &IDaaSCredentialProviderFactory{}

	tests := []struct {
		name string
		got  interface{}
		want interface{}
	}{
		{"GetDeveloperApiEndpoint", f.GetDeveloperApiEndpoint(), ""},
		{"GetOpenApiEndpoint", f.GetOpenApiEndpoint(), ""},
		{"GetIDaaSInstanceId", f.GetIDaaSInstanceId(), ""},
		{"GetClientId", f.GetClientId(), ""},
		{"GetHttpConfig", f.GetHttpConfig(), (*config.HttpConfiguration)(nil)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch v := tt.got.(type) {
			case string:
				if v != tt.want.(string) {
					t.Errorf("%s = %q, want %q", tt.name, v, tt.want)
				}
			case *config.HttpConfiguration:
				if v != nil {
					t.Errorf("%s = %v, want nil", tt.name, v)
				}
			}
		})
	}
}

// TestBoundaryInit_MultiPathFail_EnvFallback 验证多路径全失败时通过环境变量回退加载
func TestBoundaryInit_MultiPathFail_EnvFallback(t *testing.T) {
	Reset()
	defer Reset()

	os.Setenv("CLOUD_IDAAS_CLIENT_SECRET", "test_secret")
	defer os.Unsetenv("CLOUD_IDAAS_CLIENT_SECRET")

	// Create a valid config file pointed to by env var
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "env_fallback_config.json")
	cfgJSON := `{
		"clientId": "env_fallback_cid",
		"idaasInstanceId": "env_fallback_iid",
		"issuer": "https://env-fallback.example.com/oauth2",
		"tokenEndpoint": "https://env-fallback.example.com/oauth2/token",
		"scope": "api://env-fallback.example.com|read",
		"authnConfiguration": {
			"authnMethod": "client_secret_post",
			"identityType": "CLIENT",
			"clientSecretEnvVarName": "CLOUD_IDAAS_CLIENT_SECRET"
		}
	}`
	if err := os.WriteFile(cfgPath, []byte(cfgJSON), 0o644); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	// Set env var for fallback
	os.Setenv("CLOUD_IDAAS_CONFIG_PATH", cfgPath)
	defer os.Unsetenv("CLOUD_IDAAS_CONFIG_PATH")

	// Call Init with two non-existent paths — both fail, then fallback to env var
	err := Init("/nonexistent/path1.json", "/nonexistent/path2.json")
	if err != nil {
		t.Fatalf("Init should succeed via env var fallback, got: %v", err)
	}
	if got := GetClientId(); got != "env_fallback_cid" {
		t.Errorf("ClientId = %q, want %q", got, "env_fallback_cid")
	}
}
