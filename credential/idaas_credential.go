package credential

// IDaaSCredential 接口
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

	// String 返回脱敏后的凭证摘要。
	//
	// 实现 Stringer 是为了兜底：调用方一旦用 %v / %s / fmt.Println 打印
	// 整个凭证对象，输出的是脱敏文本而非明文 token。明文 access_token /
	// refresh_token 一律不出现，只保留前缀 + 长度 + SHA256 前 8 位。
	String() string
}
