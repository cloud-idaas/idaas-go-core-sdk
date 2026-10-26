package constants

// HTTP 头常量
const (
	HeaderContentType   = "Content-Type"
	HeaderAuthorization = "Authorization"
	HeaderUserAgent     = "User-Agent"
	HeaderAccept        = "Accept"
	// HeaderCookie 用于 secureCheckRedirect 跨 host 重定向时剥离会话凭证。
	HeaderCookie = "Cookie"

	// HeaderXRequestId 服务端返回的请求 ID 响应头。
	// 与 Java SDK 从响应体里读 request_id / RequestId 的做法互为补充：
	// 新接口统一走响应头，老接口只有响应体，SDK 两边都读（见 domain.HttpResponse.RequestId）。
	HeaderXRequestId = "X-Request-Id"
	// HeaderXRequestIdAlt 部分网关使用的变体写法。
	HeaderXRequestIdAlt = "X-Ca-Request-Id"

	// HeaderXAliyunEcsMetadataTokenTtlSeconds 阿里云 ECS IMDSv2 元数据 token 有效期请求头（PUT /latest/api/token 时使用）
	HeaderXAliyunEcsMetadataTokenTtlSeconds = "X-aliyun-ecs-metadata-token-ttl-seconds"
	// HeaderXAliyunEcsMetadataToken 阿里云 ECS IMDSv2 元数据 token 请求头（GET 受保护元数据时使用）
	HeaderXAliyunEcsMetadataToken = "X-aliyun-ecs-metadata-token"

	// HeaderXAwsEc2MetadataTokenTtlSeconds AWS EC2 IMDSv2 元数据 token 有效期请求头（PUT /latest/api/token 时使用）
	HeaderXAwsEc2MetadataTokenTtlSeconds = "X-aws-ec2-metadata-token-ttl-seconds"
	// HeaderXAwsEc2MetadataToken AWS EC2 IMDSv2 元数据 token 请求头（GET 受保护元数据时使用）
	HeaderXAwsEc2MetadataToken = "X-aws-ec2-metadata-token"
)

// Content-Type 常量
const (
	ContentTypeFormUrlEncoded = "application/x-www-form-urlencoded"
	ContentTypeJson           = "application/json"
	ContentTypeXml            = "application/xml"
)
