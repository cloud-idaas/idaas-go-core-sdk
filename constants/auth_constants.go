package constants

// 认证相关常量 (§13.7)
//
// 与阿里云 Java SDK AuthenticationConstants / HttpConstants 保持一致。
const (
	// K8sServiceAccountTokenPath Kubernetes Service Account Token 默认路径
	// 参考 https://kubernetes.io/docs/concepts/security/service-accounts/#get-a-token
	K8sServiceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

	// AlibabaCloudAckOidcTokenPathEnv 阿里云 ACK RRSA OIDC Token 文件路径环境变量名
	// 参考 https://help.aliyun.com/zh/ack/ack-managed-and-ack-dedicated/user-guide/use-rrsa-to-authorize-pods-to-access-different-cloud-services
	AlibabaCloudAckOidcTokenPathEnv = "ALIBABA_CLOUD_OIDC_TOKEN_FILE"

	// EcsMetadataServiceUrl 阿里云 ECS 元数据服务（IMDSv2）token 接口
	// 通过 PUT 请求 + X-aliyun-ecs-metadata-token-ttl-seconds 头获取临时 metadata token
	EcsMetadataServiceUrl = "http://100.100.100.200/latest/api/token"

	// EcsPkcs7AttestedDocumentUrlTemplate 阿里云 ECS PKCS7 attested document 接口（IMDSv2）
	// %s 处填入 URL-encoded 的 audience JSON：{"aud": idaasInstanceId, "signingTime": <unix秒>}
	EcsPkcs7AttestedDocumentUrlTemplate = "http://100.100.100.200/latest/dynamic/instance-identity/pkcs7?audience=%s"

	// EcsMetadataServiceUrl 旧常量保留作为兼容别名（指向同一个 IMDSv2 token URL）
	EcsMetadataUrl = EcsMetadataServiceUrl

	// DefaultEcsAttestedDocumentTtlSeconds attested document 默认有效期（秒）
	// 与 Java SDK 保持一致：默认 3600s，合法范围 (1200, 1314000]
	DefaultEcsAttestedDocumentTtlSeconds = 3600

	// MinEcsAttestedDocumentTtlSeconds attested document 最小有效期（秒，不含）
	MinEcsAttestedDocumentTtlSeconds = 1200

	// MaxEcsAttestedDocumentTtlSeconds attested document 最大有效期（秒，含）
	MaxEcsAttestedDocumentTtlSeconds = 1314000

	// DefaultScope 默认 scope
	DefaultScope = "openid profile email"

	// Ec2MetadataServiceUrl AWS EC2 元数据服务（IMDSv2）token 接口
	Ec2MetadataServiceUrl = "http://169.254.169.254/latest/api/token"

	// Ec2Pkcs7Url AWS EC2 PKCS7 签名接口（IMDSv2）
	Ec2Pkcs7Url = "http://169.254.169.254/latest/dynamic/instance-identity/pkcs7"

	// DefaultEc2MetadataTokenTtlSeconds AWS EC2 IMDSv2 metadata token 默认有效期（秒）
	DefaultEc2MetadataTokenTtlSeconds = 21600

	// GcpVmIdentityTokenUrlTemplate Google Cloud VM 元数据服务身份 token 接口
	//
	// 参考：https://cloud.google.com/compute/docs/instances/verifying-instance-identity
	//   GET http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity
	//       ?audience=<audience>&format=full
	//   必须携带请求头 Metadata-Flavor: Google
	//
	// %s 处填入 URL-encoded 的 audience（一般为 IDaaS issuer endpoint）。
	// format=full 表示 token 中包含 VM 实例的详细信息（project_id / instance_id / instance_name 等）。
	GcpVmIdentityTokenUrlTemplate = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=%s&format=full"

	// HeaderMetadataFlavor Google Cloud 元数据服务必须携带的请求头名
	HeaderMetadataFlavor = "Metadata-Flavor"

	// HeaderMetadataFlavorValueGoogle Google Cloud 元数据服务必须携带的请求头值
	HeaderMetadataFlavorValueGoogle = "Google"

	// AzureVmIdentityTokenUrlTemplate Azure VM IMDS Managed Identity ID Token 接口
	//
	// 参考：https://learn.microsoft.com/azure/active-directory/managed-identities-azure-resources/how-to-use-vm-token
	//   GET http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=<URL-encoded resource>
	//   必须携带请求头 Metadata: true
	//
	// %s 处填入 URL-encoded 的 resource（一般为 IDaaS issuer endpoint 的 origin，写入 token 的 aud claim）。
	// 响应体为 JSON：{"access_token":"<JWT>", "expires_on":"<unix秒字符串>", ...}
	AzureVmIdentityTokenUrlTemplate = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=%s"

	// HeaderMetadata Azure IMDS 必须携带的请求头名
	HeaderMetadata = "Metadata"

	// HeaderMetadataValueTrue Azure IMDS 必须携带的请求头值
	HeaderMetadataValueTrue = "true"

	// TokenRefreshBufferSeconds Token 过期前主动刷新的缓冲时间（秒）
	// 所有 OIDC/PKCS7 provider 统一使用此值，避免在 token 即将过期时仍返回旧值
	TokenRefreshBufferSeconds = 600 // 10 minutes

	// DefaultHumanAuthenticateClientId HUMAN 身份认证（Device Code 流程）默认 clientId
	// 与阿里云 Java SDK 保持一致
	DefaultHumanAuthenticateClientId = "iap_developer"
)
