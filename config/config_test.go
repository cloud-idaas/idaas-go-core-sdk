package config

import (
	"os"
	"testing"

	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
)

func TestIDaaSClientConfig(t *testing.T) {
	config := &IDaaSClientConfig{
		ClientId:       "test_client_id",
		InstanceId:     "test_instance_id",
		IssuerEndpoint: "https://test.example.com/oauth2",
		TokenEndpoint:  "https://test.example.com/oauth2/token",
		Scope:          "api.example.com|read",
	}

	if config.ClientId != "test_client_id" {
		t.Errorf("Expected ClientId to be 'test_client_id', got %s", config.ClientId)
	}

	if config.InstanceId != "test_instance_id" {
		t.Errorf("Expected InstanceId to be 'test_instance_id', got %s", config.InstanceId)
	}
}

func TestIdentityAuthenticationConfiguration(t *testing.T) {
	authnConfig := &IdentityAuthenticationConfiguration{
		AuthnMethod:            enums.TokenAuthnMethodClientSecretPost,
		IdentityType:           enums.AuthenticationIdentityClient,
		ClientSecretEnvVarName: "CLOUD_IDAAS_CLIENT_SECRET",
	}

	if authnConfig.AuthnMethod != enums.TokenAuthnMethodClientSecretPost {
		t.Errorf("Expected AuthnMethod to be client_secret_post, got %s", authnConfig.AuthnMethod)
	}

	if authnConfig.ClientSecretEnvVarName != "CLOUD_IDAAS_CLIENT_SECRET" {
		t.Errorf("Expected ClientSecretEnvVarName to be 'CLOUD_IDAAS_CLIENT_SECRET', got %s", authnConfig.ClientSecretEnvVarName)
	}
}

func TestHttpConfiguration(t *testing.T) {
	httpConfig := &HttpConfiguration{
		ConnectTimeout: 3000,
		ReadTimeout:    6000,
	}

	if httpConfig.ConnectTimeout != 3000 {
		t.Errorf("Expected ConnectTimeout to be 3000, got %d", httpConfig.ConnectTimeout)
	}

	if httpConfig.ReadTimeout != 6000 {
		t.Errorf("Expected ReadTimeout to be 6000, got %d", httpConfig.ReadTimeout)
	}
}

func TestConfigReaderLoadFromEnv(t *testing.T) {
	// 设置环境变量
	os.Setenv("CLOUD_IDAAS_CLIENT_ID", "test_client")
	os.Setenv("CLOUD_IDAAS_INSTANCE_ID", "test_instance")
	os.Setenv("CLOUD_IDAAS_ISSUER_ENDPOINT", "https://test.example.com/oauth2")
	os.Setenv("CLOUD_IDAAS_TOKEN_ENDPOINT", "https://test.example.com/oauth2/token")
	os.Setenv("CLOUD_IDAAS_SCOPE", "api.example.com|read")
	os.Setenv("CLOUD_IDAAS_AUTHN_METHOD", "client_secret_post")
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
	config, err := reader.LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv failed: %v", err)
	}

	if config.ClientId != "test_client" {
		t.Errorf("Expected ClientId to be 'test_client', got %s", config.ClientId)
	}

	if config.InstanceId != "test_instance" {
		t.Errorf("Expected InstanceId to be 'test_instance', got %s", config.InstanceId)
	}

	if config.AuthnConfiguration == nil {
		t.Fatal("Expected AuthnConfiguration to not be nil")
	}

	if config.AuthnConfiguration.AuthnMethod != enums.TokenAuthnMethodClientSecretPost {
		t.Errorf("Expected AuthnMethod to be client_secret_post, got %s", config.AuthnConfiguration.AuthnMethod)
	}

	if config.AuthnConfiguration.ClientSecretEnvVarName != "CLOUD_IDAAS_CLIENT_SECRET" {
		t.Errorf("Expected ClientSecretEnvVarName to be 'CLOUD_IDAAS_CLIENT_SECRET', got %s", config.AuthnConfiguration.ClientSecretEnvVarName)
	}
}

func TestConfigValidatorValidateSuccess(t *testing.T) {
	config := &IDaaSClientConfig{
		ClientId:       "test_client_id",
		InstanceId:     "test_instance_id",
		IssuerEndpoint: "https://test.example.com/oauth2",
		TokenEndpoint:  "https://test.example.com/oauth2/token",
		AuthnConfiguration: &IdentityAuthenticationConfiguration{
			AuthnMethod:            enums.TokenAuthnMethodClientSecretPost,
			IdentityType:           enums.AuthenticationIdentityClient,
			ClientSecretEnvVarName: "CLOUD_IDAAS_CLIENT_SECRET",
		},
	}

	validator := NewConfigValidator()
	err := validator.Validate(config)
	if err != nil {
		t.Errorf("Expected validation to succeed, got error: %v", err)
	}
}

func TestConfigValidatorValidateMissingClientId(t *testing.T) {
	config := &IDaaSClientConfig{
		InstanceId:     "test_instance_id",
		IssuerEndpoint: "https://test.example.com/oauth2",
		TokenEndpoint:  "https://test.example.com/oauth2/token",
		AuthnConfiguration: &IdentityAuthenticationConfiguration{
			AuthnMethod:            enums.TokenAuthnMethodClientSecretPost,
			IdentityType:           enums.AuthenticationIdentityClient,
			ClientSecretEnvVarName: "CLOUD_IDAAS_CLIENT_SECRET",
		},
	}

	validator := NewConfigValidator()
	err := validator.Validate(config)
	if err == nil {
		t.Error("Expected validation to fail for missing client_id")
	}
}

func TestConfigValidatorValidateMissingAuthnConfig(t *testing.T) {
	config := &IDaaSClientConfig{
		ClientId:       "test_client_id",
		InstanceId:     "test_instance_id",
		IssuerEndpoint: "https://test.example.com/oauth2",
		TokenEndpoint:  "https://test.example.com/oauth2/token",
	}

	validator := NewConfigValidator()
	err := validator.Validate(config)
	if err == nil {
		t.Error("Expected validation to fail for missing authn_configuration")
	}
}

// TestConfigValidator_AllAuthnMethodBranches 覆盖：
// 校验器必须对每个已支持的 authnMethod 都执行相应的字段校验。
func TestConfigValidator_AllAuthnMethodBranches(t *testing.T) {
	baseConfig := func() *IDaaSClientConfig {
		return &IDaaSClientConfig{
			ClientId:       "cid",
			InstanceId:     "iid",
			IssuerEndpoint: "https://i.example.com",
			TokenEndpoint:  "https://i.example.com/oauth2/token",
			AuthnConfiguration: &IdentityAuthenticationConfiguration{
				IdentityType: enums.AuthenticationIdentityClient,
			},
		}
	}

	cases := []struct {
		name        string
		mutate      func(*IDaaSClientConfig)
		expectError bool
		errorCode   string
	}{
		{
			name: "client_secret_jwt 缺少 ClientSecretEnvVarName",
			mutate: func(c *IDaaSClientConfig) {
				c.AuthnConfiguration.AuthnMethod = enums.TokenAuthnMethodClientSecretJwt
			},
			expectError: true,
		},
		{
			name: "client_secret_jwt 填齐 ClientSecretEnvVarName 通过",
			mutate: func(c *IDaaSClientConfig) {
				c.AuthnConfiguration.AuthnMethod = enums.TokenAuthnMethodClientSecretJwt
				c.AuthnConfiguration.ClientSecretEnvVarName = "X"
			},
			expectError: false,
		},
		{
			name: "none 模式应被拒绝 (常量已删除,用字面量验证 default 分支仍拒绝)",
			mutate: func(c *IDaaSClientConfig) {
				c.AuthnConfiguration.AuthnMethod = "none"
			},
			expectError: true,
		},
		{
			name: "pkcs7 缺少 ApplicationFederatedCredentialName",
			mutate: func(c *IDaaSClientConfig) {
				c.AuthnConfiguration.AuthnMethod = enums.TokenAuthnMethodPkcs7
			},
			expectError: true,
		},
		{
			name: "pkcs7 缺少 ClientDeployEnvironment",
			mutate: func(c *IDaaSClientConfig) {
				c.AuthnConfiguration.AuthnMethod = enums.TokenAuthnMethodPkcs7
				c.AuthnConfiguration.ApplicationFederatedCredentialName = "fed"
			},
			expectError: true,
		},
		{
			name: "pkcs7 不支持的 ClientDeployEnvironment（KUBERNETES）",
			mutate: func(c *IDaaSClientConfig) {
				c.AuthnConfiguration.AuthnMethod = enums.TokenAuthnMethodPkcs7
				c.AuthnConfiguration.ApplicationFederatedCredentialName = "fed"
				c.AuthnConfiguration.ClientDeployEnvironment = enums.ClientDeployEnvironmentKubernetes
			},
			expectError: true,
		},
		{
			name: "pkcs7 + ALIBABA_CLOUD_ECS 通过",
			mutate: func(c *IDaaSClientConfig) {
				c.AuthnConfiguration.AuthnMethod = enums.TokenAuthnMethodPkcs7
				c.AuthnConfiguration.ApplicationFederatedCredentialName = "fed"
				c.AuthnConfiguration.ClientDeployEnvironment = enums.ClientDeployEnvironmentAlibabaCloudEcs
			},
			expectError: false,
		},
		{
			name: "pkcs7 + AWS_EC2 通过",
			mutate: func(c *IDaaSClientConfig) {
				c.AuthnConfiguration.AuthnMethod = enums.TokenAuthnMethodPkcs7
				c.AuthnConfiguration.ApplicationFederatedCredentialName = "fed"
				c.AuthnConfiguration.ClientDeployEnvironment = enums.ClientDeployEnvironmentAwsEc2
			},
			expectError: false,
		},
		{
			name: "oidc 缺少 ApplicationFederatedCredentialName",
			mutate: func(c *IDaaSClientConfig) {
				c.AuthnConfiguration.AuthnMethod = enums.TokenAuthnMethodOidc
				c.AuthnConfiguration.ClientDeployEnvironment = enums.ClientDeployEnvironmentKubernetes
			},
			expectError: true,
		},
		{
			name: "oidc 缺少 ClientDeployEnvironment",
			mutate: func(c *IDaaSClientConfig) {
				c.AuthnConfiguration.AuthnMethod = enums.TokenAuthnMethodOidc
				c.AuthnConfiguration.ApplicationFederatedCredentialName = "fed"
			},
			expectError: true,
		},
		{
			name: "oidc 不支持的 ClientDeployEnvironment（ALIBABA_CLOUD_ECS）",
			mutate: func(c *IDaaSClientConfig) {
				c.AuthnConfiguration.AuthnMethod = enums.TokenAuthnMethodOidc
				c.AuthnConfiguration.ApplicationFederatedCredentialName = "fed"
				c.AuthnConfiguration.ClientDeployEnvironment = enums.ClientDeployEnvironmentAlibabaCloudEcs
			},
			expectError: true,
		},
		{
			name: "oidc 不支持的 ClientDeployEnvironment（ALIBABA_CLOUD_ACK）",
			mutate: func(c *IDaaSClientConfig) {
				c.AuthnConfiguration.AuthnMethod = enums.TokenAuthnMethodOidc
				c.AuthnConfiguration.ApplicationFederatedCredentialName = "fed"
				c.AuthnConfiguration.ClientDeployEnvironment = enums.ClientDeployEnvironmentAlibabaCloudAck
			},
			expectError: true,
		},
		{
			name: "oidc + KUBERNETES 通过",
			mutate: func(c *IDaaSClientConfig) {
				c.AuthnConfiguration.AuthnMethod = enums.TokenAuthnMethodOidc
				c.AuthnConfiguration.ApplicationFederatedCredentialName = "fed"
				c.AuthnConfiguration.ClientDeployEnvironment = enums.ClientDeployEnvironmentKubernetes
			},
			expectError: false,
		},
		{
			name: "oidc + GOOGLE_VM 通过",
			mutate: func(c *IDaaSClientConfig) {
				c.AuthnConfiguration.AuthnMethod = enums.TokenAuthnMethodOidc
				c.AuthnConfiguration.ApplicationFederatedCredentialName = "fed"
				c.AuthnConfiguration.ClientDeployEnvironment = enums.ClientDeployEnvironmentGoogleVm
			},
			expectError: false,
		},
		{
			name: "oidc + AZURE_VM 通过",
			mutate: func(c *IDaaSClientConfig) {
				c.AuthnConfiguration.AuthnMethod = enums.TokenAuthnMethodOidc
				c.AuthnConfiguration.ApplicationFederatedCredentialName = "fed"
				c.AuthnConfiguration.ClientDeployEnvironment = enums.ClientDeployEnvironmentAzureVm
			},
			expectError: false,
		},
		{
			name: "oidc + COMPUTER 缺少 oidcTokenFilePath 和 oidcTokenFilePathEnvVarName",
			mutate: func(c *IDaaSClientConfig) {
				c.AuthnConfiguration.AuthnMethod = enums.TokenAuthnMethodOidc
				c.AuthnConfiguration.ApplicationFederatedCredentialName = "fed"
				c.AuthnConfiguration.ClientDeployEnvironment = enums.ClientDeployEnvironmentComputer
			},
			expectError: true,
		},
		{
			name: "oidc + COMPUTER 配置了 oidcTokenFilePath 通过",
			mutate: func(c *IDaaSClientConfig) {
				c.AuthnConfiguration.AuthnMethod = enums.TokenAuthnMethodOidc
				c.AuthnConfiguration.ApplicationFederatedCredentialName = "fed"
				c.AuthnConfiguration.ClientDeployEnvironment = enums.ClientDeployEnvironmentComputer
				c.AuthnConfiguration.OidcTokenFilePath = "/tmp/token"
			},
			expectError: false,
		},
		{
			name: "oidc + COMPUTER 配置了 oidcTokenFilePathEnvVarName 通过",
			mutate: func(c *IDaaSClientConfig) {
				c.AuthnConfiguration.AuthnMethod = enums.TokenAuthnMethodOidc
				c.AuthnConfiguration.ApplicationFederatedCredentialName = "fed"
				c.AuthnConfiguration.ClientDeployEnvironment = enums.ClientDeployEnvironmentComputer
				c.AuthnConfiguration.OidcTokenFilePathEnvVarName = "OIDC_TOKEN_FILE_PATH"
			},
			expectError: false,
		},

		{
			name: "pca 缺少 PrivateKeyEnvVarName",
			mutate: func(c *IDaaSClientConfig) {
				c.AuthnConfiguration.AuthnMethod = enums.TokenAuthnMethodPca
				c.AuthnConfiguration.ApplicationFederatedCredentialName = "pca_fed"
				c.AuthnConfiguration.ClientX509Certificate = "PEM_CERT"
				c.AuthnConfiguration.X509CertChains = "PEM_CHAIN"
			},
			expectError: true,
		},
		{
			name: "pca 缺少 ApplicationFederatedCredentialName",
			mutate: func(c *IDaaSClientConfig) {
				c.AuthnConfiguration.AuthnMethod = enums.TokenAuthnMethodPca
				c.AuthnConfiguration.PrivateKeyEnvVarName = "K"
				c.AuthnConfiguration.ClientX509Certificate = "PEM_CERT"
				c.AuthnConfiguration.X509CertChains = "PEM_CHAIN"
			},
			expectError: true,
		},
		{
			name: "pca 缺少 ClientX509Certificate",
			mutate: func(c *IDaaSClientConfig) {
				c.AuthnConfiguration.AuthnMethod = enums.TokenAuthnMethodPca
				c.AuthnConfiguration.PrivateKeyEnvVarName = "K"
				c.AuthnConfiguration.ApplicationFederatedCredentialName = "pca_fed"
				c.AuthnConfiguration.X509CertChains = "PEM_CHAIN"
			},
			expectError: true,
		},
		{
			name: "pca 缺少 X509CertChains",
			mutate: func(c *IDaaSClientConfig) {
				c.AuthnConfiguration.AuthnMethod = enums.TokenAuthnMethodPca
				c.AuthnConfiguration.PrivateKeyEnvVarName = "K"
				c.AuthnConfiguration.ApplicationFederatedCredentialName = "pca_fed"
				c.AuthnConfiguration.ClientX509Certificate = "PEM_CERT"
			},
			expectError: true,
		},
		{
			name: "pca 填齐全部 4 个字段通过",
			mutate: func(c *IDaaSClientConfig) {
				c.AuthnConfiguration.AuthnMethod = enums.TokenAuthnMethodPca
				c.AuthnConfiguration.PrivateKeyEnvVarName = "K"
				c.AuthnConfiguration.ApplicationFederatedCredentialName = "pca_fed"
				c.AuthnConfiguration.ClientX509Certificate = "PEM_CERT"
				c.AuthnConfiguration.X509CertChains = "PEM_CHAIN"
			},
			expectError: false,
		},
		{
			name: "plugin 缺少 PluginName",
			mutate: func(c *IDaaSClientConfig) {
				c.AuthnConfiguration.AuthnMethod = enums.TokenAuthnMethodPlugin
			},
			expectError: true,
		},
		{
			name: "plugin 填齐 PluginName 通过",
			mutate: func(c *IDaaSClientConfig) {
				c.AuthnConfiguration.AuthnMethod = enums.TokenAuthnMethodPlugin
				c.AuthnConfiguration.PluginName = "alibabacloudPluginCredentialProvider"
				c.OpenApiEndpoint = "https://example.com/api"
			},
			expectError: false,
		},
		{
			name: "空 authnMethod 必须报错",
			mutate: func(c *IDaaSClientConfig) {
				c.AuthnConfiguration.AuthnMethod = ""
			},
			expectError: true,
		},
		{
			name: "未知 authnMethod 必须报错",
			mutate: func(c *IDaaSClientConfig) {
				c.AuthnConfiguration.AuthnMethod = enums.TokenAuthnMethod("unknown_method_xyz")
			},
			expectError: true,
		},
	}

	validator := NewConfigValidator()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := baseConfig()
			tc.mutate(cfg)
			err := validator.Validate(cfg)
			if tc.expectError && err == nil {
				t.Errorf("期望返回错误，但通过了校验")
			}
			if !tc.expectError && err != nil {
				t.Errorf("期望通过校验，但返回错误: %v", err)
			}
		})
	}
}

// TestConfigReader_LoadFromEnv_MissingRequired 验证 LoadFromEnv 在缺关键字段时硬报错
func TestConfigReader_LoadFromEnv_MissingRequired(t *testing.T) {
	// 清空所有相关环境变量，避免被外部污染
	for _, k := range []string{
		"CLOUD_IDAAS_CLIENT_ID", "CLOUD_IDAAS_TOKEN_ENDPOINT",
		"CLOUD_IDAAS_INSTANCE_ID", "CLOUD_IDAAS_ISSUER_ENDPOINT",
		"CLOUD_IDAAS_SCOPE", "CLOUD_IDAAS_AUTHN_METHOD",
	} {
		os.Unsetenv(k)
	}
	reader := NewConfigReader()
	_, err := reader.LoadFromEnv()
	if err == nil {
		t.Error("expected error when required env vars are missing")
	}
}

// TestNormalizeTrimmedFields_TrimsIdentityFields_PreservesScope 验证:
// Validate 入口对身份字段与 scope 应用 TrimSpace 写回(仅去首尾,内部空格保留)。
// 纯空白身份值应被 ValidateNotBlank 拦截;合法值首尾空格被清理;scope 内部分隔符空格保留。
func TestNormalizeTrimmedFields_TrimsIdentityFields_PreservesScope(t *testing.T) {
	cfg := &IDaaSClientConfig{
		ClientId:       "  test_client_id  ",
		InstanceId:     "\ttest_instance_id\n",
		IssuerEndpoint: " https://test.example.com/oauth2 ",
		TokenEndpoint:  " https://test.example.com/oauth2/token ",
		Scope:          " aud1|read aud1|write ",
		AuthnConfiguration: &IdentityAuthenticationConfiguration{
			AuthnMethod:            enums.TokenAuthnMethodClientSecretPost,
			IdentityType:           enums.AuthenticationIdentityClient,
			ClientSecretEnvVarName: "CLOUD_IDAAS_CLIENT_SECRET",
		},
	}

	validator := NewConfigValidator()
	if err := validator.Validate(cfg); err != nil {
		t.Fatalf("Validate should succeed after trim, got: %v", err)
	}

	if cfg.ClientId != "test_client_id" {
		t.Errorf("ClientId not trimmed: %q", cfg.ClientId)
	}
	if cfg.InstanceId != "test_instance_id" {
		t.Errorf("InstanceId not trimmed: %q", cfg.InstanceId)
	}
	if cfg.IssuerEndpoint != "https://test.example.com/oauth2" {
		t.Errorf("IssuerEndpoint not trimmed: %q", cfg.IssuerEndpoint)
	}
	if cfg.TokenEndpoint != "https://test.example.com/oauth2/token" {
		t.Errorf("TokenEndpoint not trimmed: %q", cfg.TokenEndpoint)
	}
	// scope 仅去首尾,内部多值分隔符空格保留(多 scope 项以空格分隔,同 audience 多 permission)。
	if cfg.Scope != "aud1|read aud1|write" {
		t.Errorf("Scope should preserve internal spaces, got: %q", cfg.Scope)
	}
}

// TestNormalizeTrimmedFields_RejectsWhitespaceIdentity 验证纯空白身份字段被拦截。
func TestNormalizeTrimmedFields_RejectsWhitespaceIdentity(t *testing.T) {
	for _, bad := range []string{" ", "\t\n", "  "} {
		cfg := &IDaaSClientConfig{
			ClientId:       bad,
			InstanceId:     "test_instance_id",
			IssuerEndpoint: "https://test.example.com/oauth2",
			TokenEndpoint:  "https://test.example.com/oauth2/token",
			AuthnConfiguration: &IdentityAuthenticationConfiguration{
				AuthnMethod:            enums.TokenAuthnMethodClientSecretPost,
				IdentityType:           enums.AuthenticationIdentityClient,
				ClientSecretEnvVarName: "CLOUD_IDAAS_CLIENT_SECRET",
			},
		}
		validator := NewConfigValidator()
		if err := validator.Validate(cfg); err == nil {
			t.Errorf("Validate should reject whitespace-only ClientId %q", bad)
		}
	}
}
