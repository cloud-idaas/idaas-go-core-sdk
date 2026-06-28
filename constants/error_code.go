package constants

// ErrorCode 常量定义 (§9.2)
// 配置类错误码 (§9.2.1)
const (
	IDaaSCredentialProviderFactoryNotInit = "IDaaSCredentialProviderFactoryNotInit"
	IDaaSInstanceIdNotFound               = "IDaaSInstanceIdNotFound"
	ClientIdNotFound                      = "ClientIdNotFound"
	IssuerEndpointNotFound                = "IssuerEndpointNotFound"
	TokenEndpointNotFound                 = "TokenEndpointNotFound"
	AuthnConfigurationNotFound            = "AuthnConfigurationNotFound"
	HumanAuthenticateClientIdNotFound     = "HumanAuthenticateClientIdNotFound"
	HumanAuthenticateScopeNotFound        = "HumanAuthenticateScopeNotFound"
	DeviceAuthorizationEndpointNotFound   = "DeviceAuthorizationEndpointNotFound"
	LoadConfigFileFailed                  = "LoadConfigFileFailed"
	DeveloperApiEndpointNotFound          = "DeveloperApiEndpointNotFound"
)

// 认证材料类错误码 (§9.2.2)
const (
	ClientSecretEnvVarNameNotFound             = "ClientSecretEnvVarNameNotFound"
	PrivateKeyEnvVarNameNotFound               = "PrivateKeyEnvVarNameNotFound"
	ApplicationFederatedCredentialNameNotFound = "ApplicationFederatedCredentialNameNotFound"
	// ClientDeployEnvironmentNotFound 当 authnMethod 为 PKCS7/OIDC 但未提供 clientDeployEnvironment 时使用
	ClientDeployEnvironmentNotFound = "ClientDeployEnvironmentNotFound"
	ClientX509CertificateNotFound   = "ClientX509CertificateNotFound"
	X509CertChainsNotFound          = "X509CertChainsNotFound"
	PluginNameNotFound              = "PluginNameNotFound"
	OpenApiEndpointNotFound         = "OpenApiEndpointNotFound"
)

// HTTP类错误码 (§9.2.3)
const (
	ConnectTimeoutNotValid = "ConnectTimeoutNotValid"
	ReadTimeoutNotValid    = "ReadTimeoutNotValid"
	ConnectTimeOut         = "ConnectTimeOut"
	ReadTimeOut            = "ReadTimeOut"
)

// 运行时类错误码 (§9.2.4)
const (
	InvalidScope                    = "InvalidScope"
	MultipleAudienceNotSupported    = "MultipleAudienceNotSupported"
	UnsupportedAuthenticationMethod = "UnsupportedAuthenticationMethod"
	// UnsupportedClientDeployEnvironment 当 clientDeployEnvironment 取值不是 ALIBABA_CLOUD_ECS / KUBERNETES 时使用
	UnsupportedClientDeployEnvironment = "UnsupportedClientDeployEnvironment"
	NotSupportedWebKey                 = "NotSupportedWebKey"
	RefreshTokenEmpty                  = "RefreshTokenEmpty"
	InvalidTokenType                   = "InvalidTokenType"
	AccessTokenNotFound                = "AccessTokenNotFound"
	IdTokenNotFound                    = "IdTokenNotFound"
	RefreshTokenNotFound               = "RefreshTokenNotFound"
	ClientError                        = "ClientError"
	ServerError                        = "ServerError"
	InvalidRequest                     = "InvalidRequest"
	UnsupportedOpenApiType             = "UnsupportedOpenApiType"
)

// 并发类错误码 (§9.2.5)
const (
	ConcurrentOperationFailed = "ConcurrentOperationFailed"
)
