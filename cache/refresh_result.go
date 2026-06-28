package cache

import "time"

// RefreshResult 泛型刷新结果结构体 (§3.3)
type RefreshResult[T any] struct {
	Value     T
	ExpiresAt time.Time
	Error     error
}

// IsExpired 判断是否已过期
func (r *RefreshResult[T]) IsExpired() bool {
	return time.Now().After(r.ExpiresAt)
}

// WillSoonExpire 判断是否即将过期
func (r *RefreshResult[T]) WillSoonExpire(threshold time.Duration) bool {
	return time.Now().Add(threshold).After(r.ExpiresAt)
}
