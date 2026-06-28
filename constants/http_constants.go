package constants

// HTTP 头常量 (§13.5)
const (
	HeaderContentType   = "Content-Type"
	HeaderAuthorization = "Authorization"
	HeaderUserAgent     = "User-Agent"
	HeaderAccept        = "Accept"

	// HeaderXAliyunEcsMetadataTokenTtlSeconds 阿里云 ECS IMDSv2 元数据 token 有效期请求头（PUT /latest/api/token 时使用）
	HeaderXAliyunEcsMetadataTokenTtlSeconds = "X-aliyun-ecs-metadata-token-ttl-seconds"
	// HeaderXAliyunEcsMetadataToken 阿里云 ECS IMDSv2 元数据 token 请求头（GET 受保护元数据时使用）
	HeaderXAliyunEcsMetadataToken = "X-aliyun-ecs-metadata-token"

	// HeaderXAwsEc2MetadataTokenTtlSeconds AWS EC2 IMDSv2 元数据 token 有效期请求头（PUT /latest/api/token 时使用）
	HeaderXAwsEc2MetadataTokenTtlSeconds = "X-aws-ec2-metadata-token-ttl-seconds"
	// HeaderXAwsEc2MetadataToken AWS EC2 IMDSv2 元数据 token 请求头（GET 受保护元数据时使用）
	HeaderXAwsEc2MetadataToken = "X-aws-ec2-metadata-token"
)

// Content-Type 常量 (§13.6)
const (
	ContentTypeFormUrlEncoded = "application/x-www-form-urlencoded"
	ContentTypeJson           = "application/json"
	ContentTypeXml            = "application/xml"
)
