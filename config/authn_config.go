package config

import (
	"encoding/json"
	"strings"

	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
)

// IdentityAuthenticationConfiguration 身份认证配置结构体 (§13.4)
type IdentityAuthenticationConfiguration struct {
	AuthnMethod  enums.TokenAuthnMethod           `json:"authnMethod"`
	IdentityType enums.AuthenticationIdentityEnum `json:"identityType"`

	// Client Secret 相关
	ClientSecretEnvVarName string `json:"clientSecretEnvVarName,omitempty"`

	// Private Key 相关
	PrivateKeyEnvVarName string `json:"privateKeyEnvVarName,omitempty"`

	// Federated Credential 相关
	ApplicationFederatedCredentialName string `json:"applicationFederatedCredentialName,omitempty"`

	// Deploy Environment
	ClientDeployEnvironment enums.ClientDeployEnvironmentEnum `json:"clientDeployEnvironment,omitempty"`

	// OIDC Token File 相关
	OidcTokenFilePath           string `json:"oidcTokenFilePath,omitempty"`
	OidcTokenFilePathEnvVarName string `json:"oidcTokenFilePathEnvVarName,omitempty"`

	// PCA (X509) 相关
	ClientX509Certificate string `json:"clientX509Certificate,omitempty"`
	X509CertChains        string `json:"x509CertChains,omitempty"`

	// Plugin 相关
	PluginName string `json:"pluginName,omitempty"`

	// Human Authentication 相关
	HumanAuthenticateClientId string `json:"humanAuthenticateClientId,omitempty"`
}

// UnmarshalJSON 自定义反序列化逻辑，对枚举字段做大小写归一化，
// 以兼容用户在 JSON 配置中使用大写形式（如 "CLIENT_SECRET_BASIC"）的写法，
// 与 Java/Python SDK 保持一致。
func (c *IdentityAuthenticationConfiguration) UnmarshalJSON(data []byte) error {
	// 使用别名类型避免递归调用 UnmarshalJSON
	type rawConfig IdentityAuthenticationConfiguration
	var raw rawConfig
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	// AuthnMethod 的枚举常量定义为小写（如 "client_secret_basic"），归一化为小写
	if raw.AuthnMethod != "" {
		raw.AuthnMethod = enums.TokenAuthnMethod(strings.ToLower(string(raw.AuthnMethod)))
	}

	// IdentityType 的枚举常量定义为大写（如 "CLIENT"、"HUMAN"），归一化为大写
	if raw.IdentityType != "" {
		raw.IdentityType = enums.AuthenticationIdentityEnum(strings.ToUpper(string(raw.IdentityType)))
	}

	// ClientDeployEnvironment 的枚举常量定义为大写（如 "ALIBABA_CLOUD_ECS"、"KUBERNETES"），归一化为大写
	if raw.ClientDeployEnvironment != "" {
		raw.ClientDeployEnvironment = enums.ClientDeployEnvironmentEnum(strings.ToUpper(string(raw.ClientDeployEnvironment)))
	}

	*c = IdentityAuthenticationConfiguration(raw)
	return nil
}
