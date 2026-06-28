package credential

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestIDaaSTokenResponse_WillSoonExpire 测试 WillSoonExpire 方法
func TestIDaaSTokenResponse_WillSoonExpire(t *testing.T) {
	tests := []struct {
		name             string
		response         IDaaSTokenResponse
		thresholdSeconds int64
		want             bool
	}{
		{
			name: "令牌已过期",
			response: IDaaSTokenResponse{
				ExpiresIn:  -10,
				ReceivedAt: time.Now().Add(-20 * time.Second),
			},
			thresholdSeconds: 30,
			want:             true,
		},
		{
			name: "ExpiresIn为0",
			response: IDaaSTokenResponse{
				ExpiresIn:  0,
				ReceivedAt: time.Now(),
			},
			thresholdSeconds: 30,
			want:             true,
		},
		{
			name: "令牌即将在阈值内过期",
			response: IDaaSTokenResponse{
				ExpiresIn:  10,
				ReceivedAt: time.Now().Add(-5 * time.Second),
			},
			thresholdSeconds: 30,
			want:             true,
		},
		{
			name: "令牌还有很长时间才过期",
			response: IDaaSTokenResponse{
				ExpiresIn:  3600,
				ReceivedAt: time.Now(),
			},
			thresholdSeconds: 30,
			want:             false,
		},
		{
			name: "令牌刚好在阈值边界（由于时间精度，可能返回true）",
			response: IDaaSTokenResponse{
				ExpiresIn:  30,
				ReceivedAt: time.Now(),
			},
			thresholdSeconds: 30,
			want:             true, // 由于执行时间差，通常会返回true
		},
		{
			name: "令牌在阈值边界外一点",
			response: IDaaSTokenResponse{
				ExpiresIn:  29,
				ReceivedAt: time.Now(),
			},
			thresholdSeconds: 30,
			want:             true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.response.WillSoonExpire(tt.thresholdSeconds)
			if got != tt.want {
				t.Errorf("WillSoonExpire(%d) = %v, want %v", tt.thresholdSeconds, got, tt.want)
			}
		})
	}
}

// TestIDaaSTokenResponse_GetAccessToken 测试 GetAccessToken 方法
func TestIDaaSTokenResponse_GetAccessToken(t *testing.T) {
	expected := "test_access_token_12345"
	response := IDaaSTokenResponse{
		AccessToken: expected,
	}

	got := response.GetAccessToken()
	if got != expected {
		t.Errorf("GetAccessToken() = %v, want %v", got, expected)
	}
}

// TestIDaaSTokenResponse_GetTokenType 测试 GetTokenType 方法
func TestIDaaSTokenResponse_GetTokenType(t *testing.T) {
	expected := "Bearer"
	response := IDaaSTokenResponse{
		TokenType: expected,
	}

	got := response.GetTokenType()
	if got != expected {
		t.Errorf("GetTokenType() = %v, want %v", got, expected)
	}
}

// TestIDaaSTokenResponse_GetExpiresIn 测试 GetExpiresIn 方法
func TestIDaaSTokenResponse_GetExpiresIn(t *testing.T) {
	var expected int64 = 3600
	response := IDaaSTokenResponse{
		ExpiresIn: expected,
	}

	got := response.GetExpiresIn()
	if got != expected {
		t.Errorf("GetExpiresIn() = %v, want %v", got, expected)
	}
}

// TestIDaaSTokenResponse_GetScope 测试 GetScope 方法
func TestIDaaSTokenResponse_GetScope(t *testing.T) {
	expected := "openid profile email"
	response := IDaaSTokenResponse{
		Scope: expected,
	}

	got := response.GetScope()
	if got != expected {
		t.Errorf("GetScope() = %v, want %v", got, expected)
	}
}

// TestIDaaSTokenResponse_GetRefreshToken 测试 GetRefreshToken 方法
func TestIDaaSTokenResponse_GetRefreshToken(t *testing.T) {
	expected := "test_refresh_token_67890"
	response := IDaaSTokenResponse{
		RefreshToken: expected,
	}

	got := response.GetRefreshToken()
	if got != expected {
		t.Errorf("GetRefreshToken() = %v, want %v", got, expected)
	}
}

// TestIDaaSTokenResponse_InterfaceImplementation 测试 IDaaSTokenResponse 是否实现 IDaaSCredential 接口
func TestIDaaSTokenResponse_InterfaceImplementation(t *testing.T) {
	// 编译时检查：如果 IDaaSTokenResponse 没有实现 IDaaSCredential 接口，这行代码会编译失败
	var _ IDaaSCredential = &IDaaSTokenResponse{}

	response := &IDaaSTokenResponse{
		AccessToken:  "access_token",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		Scope:        "openid",
		RefreshToken: "refresh_token",
	}

	// 验证所有接口方法都能正常调用
	if response.GetAccessToken() != "access_token" {
		t.Error("GetAccessToken failed")
	}
	if response.GetTokenType() != "Bearer" {
		t.Error("GetTokenType failed")
	}
	if response.GetExpiresIn() != 3600 {
		t.Error("GetExpiresIn failed")
	}
	if response.GetScope() != "openid" {
		t.Error("GetScope failed")
	}
	if response.GetRefreshToken() != "refresh_token" {
		t.Error("GetRefreshToken failed")
	}
}

// TestIDaaSTokenResponse_EmptyFields 测试空字段情况
func TestIDaaSTokenResponse_EmptyFields(t *testing.T) {
	response := IDaaSTokenResponse{}

	if response.GetAccessToken() != "" {
		t.Errorf("GetAccessToken() should return empty string, got %v", response.GetAccessToken())
	}
	if response.GetTokenType() != "" {
		t.Errorf("GetTokenType() should return empty string, got %v", response.GetTokenType())
	}
	if response.GetExpiresIn() != 0 {
		t.Errorf("GetExpiresIn() should return 0, got %v", response.GetExpiresIn())
	}
	if response.GetScope() != "" {
		t.Errorf("GetScope() should return empty string, got %v", response.GetScope())
	}
	if response.GetRefreshToken() != "" {
		t.Errorf("GetRefreshToken() should return empty string, got %v", response.GetRefreshToken())
	}
}

// TestIDaaSTokenResponse_MarshalJSON_ZeroReceivedAt 覆盖 Suggestions #19 修复：
// 零值 ReceivedAt 不应输出 "received_at": -6795364578871 这样的远古负数时间戳。
func TestIDaaSTokenResponse_MarshalJSON_ZeroReceivedAt(t *testing.T) {
	resp := IDaaSTokenResponse{
		AccessToken: "abc",
		ExpiresIn:   3600,
		// ReceivedAt 故意不设置，保持零值
	}
	data, err := json.Marshal(&resp)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	// 由于使用了 omitempty，receivedAt=0 不应出现，更不能出现负数
	body := string(data)
	if strings.Contains(body, "-") {
		t.Errorf("零值 ReceivedAt 不应输出负数时间戳，得到: %s", body)
	}
	if strings.Contains(body, `"received_at":-`) {
		t.Errorf("零值 ReceivedAt 不应输出 received_at 负数字段，得到: %s", body)
	}
}

// TestIDaaSTokenResponse_MarshalJSON_NonZeroReceivedAt 验证非零 ReceivedAt 仍然正常输出
func TestIDaaSTokenResponse_MarshalJSON_NonZeroReceivedAt(t *testing.T) {
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	resp := IDaaSTokenResponse{
		AccessToken: "abc",
		ExpiresIn:   3600,
		ReceivedAt:  fixed,
	}
	data, err := json.Marshal(&resp)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	expectedTs := strconv.FormatInt(fixed.Unix(), 10)
	if !strings.Contains(string(data), `"received_at":`+expectedTs) {
		t.Errorf("期望 received_at=%s，实际: %s", expectedTs, string(data))
	}

	// 反序列化回来必须等价
	var back IDaaSTokenResponse
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if !back.ReceivedAt.Equal(fixed) {
		t.Errorf("round-trip 失败: 期望 %v, 实际 %v", fixed, back.ReceivedAt)
	}
}
