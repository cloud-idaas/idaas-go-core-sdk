package enums

// TokenAuthnMethod Token Endpoint 认证方式枚举，与 Java SDK TokenAuthnMethod 完全对齐。
type TokenAuthnMethod string

const (
	TokenAuthnMethodClientSecretPost  TokenAuthnMethod = "client_secret_post"
	TokenAuthnMethodClientSecretBasic TokenAuthnMethod = "client_secret_basic"
	TokenAuthnMethodClientSecretJwt   TokenAuthnMethod = "client_secret_jwt"
	TokenAuthnMethodPrivateKeyJwt     TokenAuthnMethod = "private_key_jwt"

	// TokenAuthnMethodPkcs7 PKCS7 联邦认证
	// 配合 authnConfiguration.clientDeployEnvironment = ALIBABA_CLOUD_ECS 使用
	TokenAuthnMethodPkcs7 TokenAuthnMethod = "pkcs7"

	// TokenAuthnMethodPca Private CA X509 证书认证
	TokenAuthnMethodPca TokenAuthnMethod = "pca"

	// TokenAuthnMethodOidc OIDC 联邦认证
	// 配合 authnConfiguration.clientDeployEnvironment = KUBERNETES 使用
	TokenAuthnMethodOidc TokenAuthnMethod = "oidc"

	// TokenAuthnMethodPlugin 自定义插件认证
	TokenAuthnMethodPlugin TokenAuthnMethod = "plugin"
)

const (
	// Deprecated: 自 v0.1.0 起改用 TokenAuthnMethodPca，与同枚举的 Pkcs7/Oidc 命名一致
	// （Go 导出标识符使用 MixedCaps，PCA/PKCS7/OIDC 不在 golint initialism 清单，无需全大写）。
	// 两者值相同（"pca"），可直接替换；计划在 v1.0 前移除该别名。
	//
	// 保留该别名仅为向后兼容 v0.1.0-alpha.3 已发布的调用方；内部代码请勿使用，staticcheck
	// SA1019 会在引用处报警。
	TokenAuthnMethodPCA = TokenAuthnMethodPca
)
