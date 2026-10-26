package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloud-idaas/idaas-go-core-sdk/constants"
	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
)

// validBaseConfig returns a config that passes all validator checks.
// Individual tests mutate specific fields to trigger the branch under test.
func validBaseConfig() *IDaaSClientConfig {
	return &IDaaSClientConfig{
		ClientId:       "test_client_id",
		InstanceId:     "test_instance_id",
		IssuerEndpoint: "https://test.example.com/oauth2",
		TokenEndpoint:  "https://test.example.com/oauth2/token",
		AuthnConfiguration: &IdentityAuthenticationConfiguration{
			AuthnMethod:            enums.TokenAuthnMethodClientSecretBasic,
			ClientSecretEnvVarName: "CLOUD_IDAAS_CLIENT_SECRET",
		},
	}
}

// ---------------------------------------------------------------------------
// nil config returns error (no panic)
// ---------------------------------------------------------------------------

func TestBoundaryNilConfig(t *testing.T) {
	v := NewConfigValidator()
	err := v.Validate(nil)
	if err == nil {
		t.Fatalf("expected error for nil config, got nil")
	}
}

// ---------------------------------------------------------------------------
// client_secret_basic/post missing ClientSecretEnvVarName
// ---------------------------------------------------------------------------

func TestBoundaryClientSecretMissing(t *testing.T) {
	tests := []struct {
		name    string
		method  enums.TokenAuthnMethod
		secret  string
		wantErr bool
	}{
		{"basic_no_secret", enums.TokenAuthnMethodClientSecretBasic, "", true},
		{"post_no_secret", enums.TokenAuthnMethodClientSecretPost, "", true},
		{"basic_with_secret", enums.TokenAuthnMethodClientSecretBasic, "CLOUD_IDAAS_CLIENT_SECRET", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validBaseConfig()
			cfg.AuthnConfiguration.AuthnMethod = tt.method
			cfg.AuthnConfiguration.ClientSecretEnvVarName = tt.secret
			v := NewConfigValidator()
			err := v.Validate(cfg)
			if tt.wantErr && err == nil {
				t.Errorf("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// private_key_jwt credential validation
// ---------------------------------------------------------------------------

func TestBoundaryPrivateKeyJwt(t *testing.T) {
	tests := []struct {
		name       string
		privateKey string
		wantErr    bool
	}{
		{"missing_private_key", "", true},
		{"has_private_key", "CLOUD_IDAAS_PRIVATE_KEY", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validBaseConfig()
			cfg.AuthnConfiguration.AuthnMethod = enums.TokenAuthnMethodPrivateKeyJwt
			cfg.AuthnConfiguration.ClientSecretEnvVarName = ""
			cfg.AuthnConfiguration.PrivateKeyEnvVarName = tt.privateKey
			v := NewConfigValidator()
			err := v.Validate(cfg)
			if tt.wantErr && err == nil {
				t.Errorf("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// validateHttpConfiguration timeout range
// ---------------------------------------------------------------------------

func TestBoundaryHttpTimeoutRange(t *testing.T) {
	tests := []struct {
		name    string
		httpCfg *HttpConfiguration
		wantErr bool
	}{
		{"connect_1999", &HttpConfiguration{ConnectTimeout: 1999, ReadTimeout: 5000}, true},
		{"connect_2000", &HttpConfiguration{ConnectTimeout: 2000, ReadTimeout: 5000}, false},
		{"connect_60000", &HttpConfiguration{ConnectTimeout: 60000, ReadTimeout: 5000}, false},
		{"connect_60001", &HttpConfiguration{ConnectTimeout: 60001, ReadTimeout: 5000}, true},
		{"connect_neg1", &HttpConfiguration{ConnectTimeout: -1, ReadTimeout: 5000}, true},
		{"read_1999", &HttpConfiguration{ConnectTimeout: 5000, ReadTimeout: 1999}, true},
		{"read_2000", &HttpConfiguration{ConnectTimeout: 5000, ReadTimeout: 2000}, false},
		{"read_60000", &HttpConfiguration{ConnectTimeout: 5000, ReadTimeout: 60000}, false},
		{"read_60001", &HttpConfiguration{ConnectTimeout: 5000, ReadTimeout: 60001}, true},
		{"connect0_read5000", &HttpConfiguration{ConnectTimeout: 0, ReadTimeout: 5000}, false},
		{"both_zero", &HttpConfiguration{ConnectTimeout: 0, ReadTimeout: 0}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validBaseConfig()
			cfg.HttpConfiguration = tt.httpCfg
			v := NewConfigValidator()
			err := v.Validate(cfg)
			if tt.wantErr && err == nil {
				t.Errorf("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// validateHttpsUrl non-HTTPS rejection
// ---------------------------------------------------------------------------

func TestBoundaryHttpsUrlRejection(t *testing.T) {
	tests := []struct {
		name          string
		issuer        string
		allowInsecure bool
		wantErr       bool
	}{
		{"http_no_insecure", "http://host/path", false, true},
		{"http_with_insecure", "http://host/path", true, false},
		{"ftp_with_insecure", "ftp://host/path", true, true},
		{"ftp_no_insecure", "ftp://host/path", false, true},
		{"https_empty_host", "https://", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validBaseConfig()
			cfg.IssuerEndpoint = tt.issuer
			cfg.TokenEndpoint = "https://valid.example.com/token"
			cfg.AllowInsecureEndpoint = tt.allowInsecure
			v := NewConfigValidator()
			err := v.Validate(cfg)
			if tt.wantErr && err == nil {
				t.Errorf("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// validateIdentityType default branch
// ---------------------------------------------------------------------------

func TestBoundaryInvalidIdentityType(t *testing.T) {
	cfg := validBaseConfig()
	cfg.AuthnConfiguration.IdentityType = enums.AuthenticationIdentityEnum("INVALID")
	v := NewConfigValidator()
	err := v.Validate(cfg)
	if err == nil {
		t.Fatalf("expected error for invalid identity type, got nil")
	}
}

// ---------------------------------------------------------------------------
// missing required fields
// ---------------------------------------------------------------------------

func TestBoundaryMissingFields(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(cfg *IDaaSClientConfig)
		wantErr bool
	}{
		{"missing_instance_id", func(c *IDaaSClientConfig) { c.InstanceId = "" }, true},
		{"missing_issuer_endpoint", func(c *IDaaSClientConfig) { c.IssuerEndpoint = "" }, true},
		{"missing_token_endpoint", func(c *IDaaSClientConfig) { c.TokenEndpoint = "" }, true},
		{"non_https_issuer", func(c *IDaaSClientConfig) { c.IssuerEndpoint = "http://host/path" }, true},
		{"non_https_token", func(c *IDaaSClientConfig) { c.TokenEndpoint = "http://host/path" }, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validBaseConfig()
			tt.modify(cfg)
			v := NewConfigValidator()
			err := v.Validate(cfg)
			if tt.wantErr && err == nil {
				t.Errorf("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// optional endpoint rejection paths
// ---------------------------------------------------------------------------

func TestBoundaryOptionalEndpointRejection(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(cfg *IDaaSClientConfig)
		wantErr bool
	}{
		{"device_auth_http", func(c *IDaaSClientConfig) { c.DeviceAuthorizationEndpoint = "http://host" }, true},
		{"dev_api_http", func(c *IDaaSClientConfig) { c.DeveloperApiEndpoint = "http://host" }, true},
		{"open_api_http", func(c *IDaaSClientConfig) { c.OpenApiEndpoint = "http://host" }, true},
		{"open_api_https", func(c *IDaaSClientConfig) { c.OpenApiEndpoint = "https://example.com/api" }, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validBaseConfig()
			tt.modify(cfg)
			v := NewConfigValidator()
			err := v.Validate(cfg)
			if tt.wantErr && err == nil {
				t.Errorf("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// plugin with PluginName but missing OpenApiEndpoint
// ---------------------------------------------------------------------------

func TestBoundaryPluginMissingOpenApi(t *testing.T) {
	cfg := validBaseConfig()
	cfg.AuthnConfiguration.AuthnMethod = enums.TokenAuthnMethodPlugin
	cfg.AuthnConfiguration.ClientSecretEnvVarName = ""
	cfg.AuthnConfiguration.PluginName = "test"
	cfg.OpenApiEndpoint = ""
	v := NewConfigValidator()
	err := v.Validate(cfg)
	if err == nil {
		t.Fatalf("expected error for plugin without openApiEndpoint, got nil")
	}
}

// ---------------------------------------------------------------------------
// LoadFromFile non-not-exist read error
// ---------------------------------------------------------------------------

func TestBoundaryLoadFromFilePermissionDenied(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("cannot test permission denied as root")
	}

	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "unreadable.json")
	if err := os.WriteFile(filePath, []byte("{}"), 0o644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}
	if err := os.Chmod(filePath, 0o000); err != nil {
		t.Fatalf("failed to chmod file: %v", err)
	}
	// Restore permissions so t.TempDir cleanup can remove the file.
	defer os.Chmod(filePath, 0o644)

	reader := NewConfigReader()
	_, err := reader.LoadFromFile(filePath)
	if err == nil {
		t.Fatalf("expected error for unreadable file, got nil")
	}
	// The error should be a read failure, not a "not found" error.
	if strings.Contains(err.Error(), "not found") {
		t.Errorf("expected a read error (not 'not found'), got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// LoadWithPriority default config file exists
// ---------------------------------------------------------------------------

func TestBoundaryLoadWithPriorityDefaultFile(t *testing.T) {
	// constants.DefaultConfigPath is computed at package init time from os.UserHomeDir().
	// We create the file at the already-computed path and clean up afterwards.

	// Ensure CLOUD_IDAAS_CONFIG_PATH does not interfere.
	oldConfigPath := os.Getenv(constants.EnvConfigPathKey)
	os.Unsetenv(constants.EnvConfigPathKey)
	defer func() {
		if oldConfigPath != "" {
			os.Setenv(constants.EnvConfigPathKey, oldConfigPath)
		}
	}()

	// 默认路径隔离到测试临时目录。原实现直接覆写真实的 ~/.cloud_idaas/client-config.json
	// （备份-还原窗口内进程被杀会损坏用户配置，且 0600 权限会被降成 0644）。
	restore := constants.DefaultConfigPath
	constants.DefaultConfigPath = filepath.Join(t.TempDir(), "client-config.json")
	defer func() { constants.DefaultConfigPath = restore }()

	configJSON := `{
		"clientId": "default_test_client",
		"tokenEndpoint": "https://test.example.com/token"
	}`

	if err := os.WriteFile(constants.DefaultConfigPath, []byte(configJSON), 0o600); err != nil {
		t.Fatalf("failed to write default config file %s: %v", constants.DefaultConfigPath, err)
	}

	reader := NewConfigReader()
	cfg, err := reader.LoadWithPriority("")
	if err != nil {
		t.Fatalf("expected successful load from default config file, got error: %v", err)
	}
	if cfg == nil {
		t.Fatalf("expected non-nil config")
	}
	if cfg.ClientId != "default_test_client" {
		t.Errorf("expected ClientId 'default_test_client', got '%s'", cfg.ClientId)
	}
}

// ---------------------------------------------------------------------------
// LoadFromEnv private_key_jwt case + implicit default
// ---------------------------------------------------------------------------

func TestBoundaryLoadFromEnvAuthnMethod(t *testing.T) {
	tests := []struct {
		name        string
		authnMethod string
		checkFunc   func(t *testing.T, cfg *IDaaSClientConfig)
	}{
		{
			name:        "private_key_jwt_sets_private_key_env",
			authnMethod: "private_key_jwt",
			checkFunc: func(t *testing.T, cfg *IDaaSClientConfig) {
				if cfg.AuthnConfiguration.PrivateKeyEnvVarName != constants.EnvVarPrivateKey {
					t.Errorf("expected PrivateKeyEnvVarName=%s, got '%s'",
						constants.EnvVarPrivateKey, cfg.AuthnConfiguration.PrivateKeyEnvVarName)
				}
			},
		},
		{
			name:        "pkcs7_sets_no_credential_env",
			authnMethod: "pkcs7",
			checkFunc: func(t *testing.T, cfg *IDaaSClientConfig) {
				if cfg.AuthnConfiguration.ClientSecretEnvVarName != "" {
					t.Errorf("expected empty ClientSecretEnvVarName, got '%s'",
						cfg.AuthnConfiguration.ClientSecretEnvVarName)
				}
				if cfg.AuthnConfiguration.PrivateKeyEnvVarName != "" {
					t.Errorf("expected empty PrivateKeyEnvVarName, got '%s'",
						cfg.AuthnConfiguration.PrivateKeyEnvVarName)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv(constants.EnvVarClientId, "test_client")
			os.Setenv(constants.EnvVarTokenEndpoint, "https://test.example.com/token")
			os.Setenv(constants.EnvVarAuthnMethod, tt.authnMethod)

			defer func() {
				os.Unsetenv(constants.EnvVarClientId)
				os.Unsetenv(constants.EnvVarTokenEndpoint)
				os.Unsetenv(constants.EnvVarAuthnMethod)
			}()

			reader := NewConfigReader()
			cfg, err := reader.LoadFromEnv()
			if err != nil {
				t.Fatalf("LoadFromEnv failed: %v", err)
			}
			if cfg == nil {
				t.Fatalf("expected non-nil config")
			}
			if cfg.AuthnConfiguration == nil {
				t.Fatalf("expected non-nil AuthnConfiguration")
			}
			tt.checkFunc(t, cfg)
		})
	}
}
