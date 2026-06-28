package enums

// TokenAuthnMethod Token Endpoint 认证方式枚举，与 Java SDK TokenAuthnMethod 完全对齐。
type TokenAuthnMethod string

const (
	// TokenAuthnMethodNone 不使用客户端认证（public client）
	TokenAuthnMethodNone TokenAuthnMethod = "none"

	TokenAuthnMethodClientSecretPost  TokenAuthnMethod = "client_secret_post"
	TokenAuthnMethodClientSecretBasic TokenAuthnMethod = "client_secret_basic"
	TokenAuthnMethodClientSecretJwt   TokenAuthnMethod = "client_secret_jwt"
	TokenAuthnMethodPrivateKeyJwt     TokenAuthnMethod = "private_key_jwt"

	// TokenAuthnMethodPkcs7 PKCS7 联邦认证
	// 配合 authnConfiguration.clientDeployEnvironment = ALIBABA_CLOUD_ECS 使用
	TokenAuthnMethodPkcs7 TokenAuthnMethod = "pkcs7"

	// TokenAuthnMethodPCA Private CA X509 证书认证
	TokenAuthnMethodPCA TokenAuthnMethod = "pca"

	// TokenAuthnMethodOidc OIDC 联邦认证
	// 配合 authnConfiguration.clientDeployEnvironment = KUBERNETES 使用
	TokenAuthnMethodOidc TokenAuthnMethod = "oidc"

	// TokenAuthnMethodPlugin 自定义插件认证
	TokenAuthnMethodPlugin TokenAuthnMethod = "plugin"
)
