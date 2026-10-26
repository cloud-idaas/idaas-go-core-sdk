package util

import (
	"math"
	"testing"
	"time"
)

// TestClampExpiresInSeconds 验证 expires_in 上限钳位,从源头消除 int64 纳秒乘法溢出。
func TestClampExpiresInSeconds(t *testing.T) {
	tests := []struct {
		name  string
		input int64
		want  int64
	}{
		{"within range", 3600, 3600},
		{"exactly max", MaxExpiresInSeconds, MaxExpiresInSeconds},
		{"over max clamped", MaxExpiresInSeconds + 1, MaxExpiresInSeconds},
		{"huge int64 clamped", math.MaxInt64, MaxExpiresInSeconds},
		{"zero left as-is", 0, 0},
		{"negative left as-is (upper clamp only)", -5, -5},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClampExpiresInSeconds(tc.input); got != tc.want {
				t.Errorf("ClampExpiresInSeconds(%d) = %d, want %d", tc.input, got, tc.want)
			}
		})
	}
}

// TestDurationFromSeconds 验证秒→Duration 转换不会因溢出回绕为负值。
func TestDurationFromSeconds(t *testing.T) {
	// 正常值。
	if got := DurationFromSeconds(60); got != 60*time.Second {
		t.Errorf("DurationFromSeconds(60) = %v, want 60s", got)
	}
	// 超大值经钳位后为正值(1 年),绝不回绕为负。
	huge := DurationFromSeconds(math.MaxInt64)
	if huge <= 0 {
		t.Errorf("DurationFromSeconds(MaxInt64) must not overflow to <=0, got %v", huge)
	}
	if huge != time.Duration(MaxExpiresInSeconds)*time.Second {
		t.Errorf("DurationFromSeconds(MaxInt64) = %v, want %v (1 year)", huge,
			time.Duration(MaxExpiresInSeconds)*time.Second)
	}
}

// TestExtractAudienceFromScope 验证从整 scope 字符串提取首个 audience。
func TestExtractAudienceFromScope(t *testing.T) {
	// 含 audience|permission 格式的 item。
	aud, err := ExtractAudienceFromScope("audience|read other|write")
	if err != nil {
		t.Fatalf("expected audience, got error: %v", err)
	}
	if aud != "audience" && aud != "other" {
		// SplitScope 排序后取第一个成功结果,两个均合法。
		t.Errorf("expected a valid audience, got %q", aud)
	}
	// 单 item。
	aud2, err := ExtractAudienceFromScope("myapi|read")
	if err != nil {
		t.Fatalf("expected audience for single item, got error: %v", err)
	}
	if aud2 != "myapi" {
		t.Errorf("expected myapi, got %q", aud2)
	}
}

// TestExtractAudienceFromScope_NoAudience 全部 item 无管道分隔 → 错误。
func TestExtractAudienceFromScope_NoAudience(t *testing.T) {
	_, err := ExtractAudienceFromScope("plain openid")
	if err == nil {
		t.Error("expected error when no audience separator found in any scope item")
	}
	// 空串也返回错误(无 item 命中)。
	_, err = ExtractAudienceFromScope("")
	if err == nil {
		t.Error("expected error for empty scope")
	}
}
