package enums

// TokenState 枚举。//
// 表示当前凭证缓存的健康状态,供 HealthReporter 上报。
// GA 阶段才接入实际行为,beta 阶段仅占位。
type TokenState string

const (
	// TokenStateUnknown 未初始化,尚未获取过凭证。
	TokenStateUnknown TokenState = "UNKNOWN"
	// TokenStateHealthy 凭证有效且未进入预取窗口。
	TokenStateHealthy TokenState = "HEALTHY"
	// TokenStateExpiring 凭证仍在有效期内但已进入预取窗口,后台刷新已触发。
	TokenStateExpiring TokenState = "EXPIRING"
	// TokenStateExpired 凭证已过期,正在按 StaleValueBehavior 决定阻塞或降级。
	TokenStateExpired TokenState = "EXPIRED"
	// TokenStateRefreshing 刷新请求正在进行(同步阻塞或后台异步)。
	TokenStateRefreshing TokenState = "REFRESHING"
	// TokenStateDegraded 凭证过期且刷新失败,正在返回陈旧值(降级模式)。
	TokenStateDegraded TokenState = "DEGRADED"
)
