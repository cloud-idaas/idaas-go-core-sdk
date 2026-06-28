package credential

// IDaaSCredential 接口 (§3.1)
// 表示一个 IDaaS 凭证，包含访问令牌等信息
type IDaaSCredential interface {
	// GetAccessToken 获取访问令牌
	GetAccessToken() string

	// GetTokenType 获取令牌类型
	GetTokenType() string

	// GetExpiresIn 获取过期时间（秒）
	GetExpiresIn() int64

	// GetScope 获取授权范围
	GetScope() string

	// GetRefreshToken 获取刷新令牌
	GetRefreshToken() string
}
