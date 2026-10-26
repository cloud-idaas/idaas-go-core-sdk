package cache

import (
	"testing"
	"time"

	"github.com/cloud-idaas/idaas-go-core-sdk/util"
)

// expires_in 超大值不能让 time.Duration 乘法溢出回绕为负值,
// 否则 ExpiresAt 落到过去 → 每次 Get 触发刷新 (缓存自 DoS)。
func TestNewRefreshResult_OverflowExpiresIn_Clamped(t *testing.T) {
	base := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	mock := NewMockClock(base)
	SetClock(mock)
	defer SetClock(&SystemClock{})

	// 99999999999 秒 (~3170 年) 远超 time.Duration 乘法溢出阈值 (~100 年),
	// 未钳位时 expiresAt 会回绕到过去。钳位后应落到 base + 1 年(且仍在未来)。
	result, err := NewRefreshResult("tok", base, 99999999999)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.ExpiresAt.After(base) {
		t.Fatalf("ExpiresAt %v should be in the future (after base %v); overflow not clamped",
			result.ExpiresAt, base)
	}
	// 钳位上限 = 1 年
	maxExpiresAt := base.Add(util.DurationFromSeconds(util.MaxExpiresInSeconds))
	if result.ExpiresAt.After(maxExpiresAt) {
		t.Fatalf("ExpiresAt %v exceeds 1-year clamp ceiling %v", result.ExpiresAt, maxExpiresAt)
	}
	// 刚构造的结果不应判为已过期
	if result.IsExpired() {
		t.Fatalf("freshly-built result must not be IsExpired; ExpiresAt=%v now=%v",
			result.ExpiresAt, GetClock().Now())
	}
}

// 边界——正好等于上限时仍正常,不报错也不溢出。
func TestNewRefreshResult_ExactlyAtClampCeiling(t *testing.T) {
	base := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	result, err := NewRefreshResult("tok", base, util.MaxExpiresInSeconds)
	if err != nil {
		t.Fatalf("unexpected error at ceiling: %v", err)
	}
	want := base.Add(util.DurationFromSeconds(util.MaxExpiresInSeconds))
	if !result.ExpiresAt.Equal(want) {
		t.Fatalf("ExpiresAt = %v, want %v", result.ExpiresAt, want)
	}
}
