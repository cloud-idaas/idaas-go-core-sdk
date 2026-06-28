package cache

import "time"

// Clock 时钟接口（可注入，用于测试）
type Clock interface {
	Now() time.Time
}

// SystemClock 系统时钟实现
type SystemClock struct{}

func (c *SystemClock) Now() time.Time {
	return time.Now()
}
