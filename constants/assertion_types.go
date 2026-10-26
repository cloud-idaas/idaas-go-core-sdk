package constants

// client_assertion_type URN 常量
const (
	// AssertionTypeJwtBearer 标准 JWT Bearer 客户端断言（用于 private_key_jwt / client_secret_jwt）
	AssertionTypeJwtBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

	// AssertionTypeIdTokenBearer OIDC ID Token Bearer（用于 OIDC 联邦认证，如 kubernetes / computer）
	AssertionTypeIdTokenBearer = "urn:cloud:idaas:params:oauth:client-assertion-type:id-token-bearer"

	// AssertionTypePkcs7Bearer PKCS#7 签名 Bearer（用于阿里云 ECS PKCS#7 签名认证）
	AssertionTypePkcs7Bearer = "urn:cloud:idaas:params:oauth:client-assertion-type:pkcs7-bearer"

	// AssertionTypeX509JwtBearer X509 证书 JWT Bearer（用于 PCA 认证）
	AssertionTypeX509JwtBearer = "urn:cloud:idaas:params:oauth:client-assertion-type:x509-jwt-bearer"
)

// OAuth2 PrivateCA 相关 Form 参数（ 扩展）
const (
	ParamClientX509                         = "client_x509"
	ParamClientX509Chain                    = "client_x509_chain"
	ParamApplicationFederatedCredentialName = "application_federated_credential_name"
)
