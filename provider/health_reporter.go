package provider

import (
	"time"

	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
)

// HealthReporter 暴露凭证缓存的运行时健康状态，供宿主应用 /health、/ready 探针
// 直接读取，无需自维护"上次刷新时间""是否降级"的并行账本。
// beta 阶段仅定义接口，GA 由 CachedResultSupplier 接入实现。
// 所有方法必须并发安全、永不 panic、永不阻塞（读快照即可）。
type HealthReporter interface {
	Healthy() bool
	TokenState() enums.TokenState
	LastRefreshTime() time.Time
	LastRefreshError() error
	ExpiresAt() time.Time
}
