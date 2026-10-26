package cache

import (
	"strconv"
	"sync"
	"time"

	"github.com/cloud-idaas/idaas-go-core-sdk/constants"
	"github.com/cloud-idaas/idaas-go-core-sdk/errors"
	"github.com/cloud-idaas/idaas-go-core-sdk/util"
)

// RefreshResult 泛型刷新结果。双时间点模型对齐 Java/Python：
// StaleTime=expiresAt-expiresIn/5(80%) 过此返回旧值并异步刷新；
// PrefetchTime=expiresAt-expiresIn/3(67%) 过此触发后台预取；
// ExpiresAt=真实过期时间，用于 jitter 区间收缩（Go 超集）。
// Error 字段已移除（破坏性变更）：错误改由 Refresh 的 error 返回值承担。
type RefreshResult[T any] struct {
	Value        T
	StaleTime    time.Time // expiresAt - expiresIn/5 (80%)
	PrefetchTime time.Time // expiresAt - expiresIn/3 (67%)
	ExpiresAt    time.Time // 真实过期时间，用于 jitter 区间收缩
}

// IsExpired 判断是否已过期 (使用注入的 Clock)。
func (r *RefreshResult[T]) IsExpired() bool {
	return GetClock().Now().After(r.ExpiresAt)
}

// IsStale 判断是否进入 stale 阶段（已过 StaleTime 但未过 ExpiresAt）。
func (r *RefreshResult[T]) IsStale() bool {
	now := GetClock().Now()
	return now.After(r.StaleTime) && !now.After(r.ExpiresAt)
}

// ShouldPrefetch 判断是否到达预取时间点。
func (r *RefreshResult[T]) ShouldPrefetch() bool {
	return GetClock().Now().After(r.PrefetchTime)
}

// WillSoonExpire 判断是否即将过期（兼容旧接口，threshold 参数保留）。
func (r *RefreshResult[T]) WillSoonExpire(threshold time.Duration) bool {
	return GetClock().Now().Add(threshold).After(r.ExpiresAt)
}

// defaultClock 包级默认时钟，可被测试替换。
var (
	defaultClock Clock = &SystemClock{}
	clockMu      sync.RWMutex
)

// SetClock 替换包级时钟（测试用）。
//
// 线程安全 (修复)：使用 RWMutex 保护读写，避免并发 SetClock 的 data race。
// 生产代码不调用此函数；仅测试场景需要替换时钟。
func SetClock(c Clock) {
	clockMu.Lock()
	defaultClock = c
	clockMu.Unlock()
}

// GetClock 返回当前包级时钟。
func GetClock() Clock {
	clockMu.RLock()
	defer clockMu.RUnlock()
	return defaultClock
}

// NewRefreshResult 构造 RefreshResult 并自动计算 StaleTime / PrefetchTime。
// expiresIn 单位秒（与 OAuth2 expires_in 一致），receivedAt 零值时用 Clock.Now()。
// StaleTime/PrefetchTime 在 80%/67% 基准上叠加 jitter（区间收缩，非钳位到端点），
// 防同一镜像多副本同时刷新惊群；收缩逻辑见 cache/jitter.go。
func NewRefreshResult[T any](value T, receivedAt time.Time, expiresIn int64) (RefreshResult[T], error) {
	// expires_in ≤ 0 产生退化缓存 → 刷新风暴：0 值立即过期（每次 Get 同步刷新），
	// 负值语义反转（StaleTime > ExpiresAt）。拒绝非正数。
	if expiresIn <= 0 {
		return RefreshResult[T]{}, errors.NewCacheError(
			constants.InvalidExpiresIn,
			"expires_in must be a positive integer, got: "+strconv.FormatInt(expiresIn, 10),
			nil,
		)
	}

	if receivedAt.IsZero() {
		receivedAt = GetClock().Now()
	}
	// SEIdP 可控的超大 expires_in 会让 int64 纳秒乘法溢出回绕为负值，ExpiresAt 落到过去 →
	// 每次 Get 触发刷新（缓存自 DoS）。钳位到 [1, 1年] 再换算，从源头消除溢出。
	expiresIn = util.ClampExpiresInSeconds(expiresIn)
	expiresInDur := util.DurationFromSeconds(expiresIn)
	expiresAt := receivedAt.Add(expiresInDur)
	baseStale := expiresAt.Add(-expiresInDur / 5)    // 80%
	basePrefetch := expiresAt.Add(-expiresInDur / 3) // 67%
	// PrefetchTime 必须早于 StaleTime(prefetch-before-stale 设计意图)。
	// 两个时间点各自独立 jitter 时,短/中 TTL(expires_in < 50min)下 jitter 区间收缩
	// 会把 lo 塌缩为 0,使 PrefetchTime 可落在 StaleTime 之后(实测 E=300s 倒置概率≈21%、
	// E=900s≈28%);倒置窗口 [StaleTime, PrefetchTime] 内值已 stale 但 prefetch 尚未触发,
	// Block 行为退化到同步刷新(延迟尖峰)。先算 StaleTime,再把 PrefetchTime 的 jitter
	// 上界收到 StaleTime(ceiling = staleTime - SafetyMargin),既保区间内随机(不钳位、
	// 不退化)又恢复 PrefetchTime < StaleTime 不变量。长 TTL 下行为与独立 jitter 等价。
	staleTime := jitter(baseStale, expiresAt)
	return RefreshResult[T]{
		Value:        value,
		StaleTime:    staleTime,
		PrefetchTime: jitter(basePrefetch, staleTime),
		ExpiresAt:    expiresAt,
	}, nil
}
