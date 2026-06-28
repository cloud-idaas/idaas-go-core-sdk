package config

// IDaaSClientConfig 完整配置结构体 (§13.4)
//
// 注意：阿里云 IDaaS 官方配置规范中**没有顶层 deployEnvironment 字段**。
// 部署环境字段位于 authnConfiguration.clientDeployEnvironment，
// 仅用于 PKCS7 / OIDC 两种 authnMethod。详见 IdentityAuthenticationConfiguration。
type IDaaSClientConfig struct {
	// 基础配置
	ClientId                    string `json:"clientId"`
	InstanceId                  string `json:"idaasInstanceId"`
	IssuerEndpoint              string `json:"issuer"`
	TokenEndpoint               string `json:"tokenEndpoint"`
	DeviceAuthorizationEndpoint string `json:"deviceAuthorizationEndpoint,omitempty"`
	DeveloperApiEndpoint        string `json:"developerApiEndpoint,omitempty"`
	OpenApiEndpoint             string `json:"openApiEndpoint,omitempty"`

	// 认证配置
	AuthnConfiguration *IdentityAuthenticationConfiguration `json:"authnConfiguration,omitempty"`

	// HTTP 配置
	HttpConfiguration *HttpConfiguration `json:"httpConfiguration,omitempty"`

	// Scope
	Scope string `json:"scope,omitempty"`
}
