package util

import "time"

// MaxExpiresInSeconds 是允许的 expires_in 上限 (秒)。
//
// 背景 (SE):OAuth2 token 响应的 expires_in 是 IdP 可控的 int64,
// 上限可达 9.2e18。直接做 time.Duration(expiresIn) * time.Second (int64 纳秒乘法)
// 在 expiresIn 超过 ~3.17e9 秒 (~100 年) 时会回绕为负值,使 ExpiresAt 落到过去,
// 导致每次 Get 都触发刷新 → 缓存自 DoS。
//
// 这里把 expires_in 钳位到 1 年,既覆盖任何合理的长期 token,又杜绝溢出。
// 钳位而非拒绝:合法的长效 token 仍可用,只是 TTL 不超过 1 年。
const MaxExpiresInSeconds int64 = 365 * 24 * 3600

// ClampExpiresInSeconds 把 expires_in 钳位到 [1, MaxExpiresInSeconds]。
//
// 调用方在把 expires_in 转成 time.Duration 前调用此函数,从源头消除溢出。
// 非正值(<=0)不在此处理——仍由上层拒绝(退化缓存守卫),这里只负责上限。
func ClampExpiresInSeconds(expiresIn int64) int64 {
	if expiresIn > MaxExpiresInSeconds {
		return MaxExpiresInSeconds
	}
	return expiresIn
}

// DurationFromSeconds 把 expires_in (秒) 安全地转成 time.Duration,
// 内部先钳位,杜绝 int64 纳秒乘法溢出回绕为负值。
func DurationFromSeconds(expiresIn int64) time.Duration {
	return time.Duration(ClampExpiresInSeconds(expiresIn)) * time.Second
}
