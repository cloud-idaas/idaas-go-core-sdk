package credential

import (
	"strings"
	"testing"
	"time"
)

// UnmarshalJSON 两个未覆盖分支
//
// json.Unmarshal 失败分支
// aux.ReceivedAt <= 0 时回退到 time.Now()
//
// 同时覆盖 63 行（aux.ReceivedAt > 0 时直接设置）作为对照。

func TestBoundary_T16_UnmarshalJSON_Branches(t *testing.T) {
	tests := []struct {
		name          string
		raw           string
		wantErr       bool
		wantReceived  bool  // 是否期望 ReceivedAt 被设为非零值
		wantExactTime int64 // >0 时校验 ReceivedAt 精确等于该 unix 时间戳
	}{
		{
			name:         "畸形 JSON — json.Unmarshal 失败",
			raw:          `{"access_token":}`,
			wantErr:      true,
			wantReceived: false,
		},
		{
			name:         "无 received_at 字段 — 回退到 time.Now()",
			raw:          `{"access_token":"abc","token_type":"Bearer","expires_in":3600}`,
			wantErr:      false,
			wantReceived: true, // ReceivedAt 应被设为非零值
		},
		{
			name:          "received_at=0 — 回退到 time.Now()",
			raw:           `{"access_token":"abc","token_type":"Bearer","expires_in":3600,"received_at":0}`,
			wantErr:       false,
			wantReceived:  true, // ReceivedAt 应被设为非零值
			wantExactTime: 0,    // 不校验精确值，只校验非零
		},
		{
			name:          "received_at>0 — 直接使用 (line 63)",
			raw:           `{"access_token":"abc","token_type":"Bearer","expires_in":3600,"received_at":1700000000}`,
			wantErr:       false,
			wantReceived:  true,
			wantExactTime: 1700000000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var resp IDaaSTokenResponse
			err := resp.UnmarshalJSON([]byte(tt.raw))

			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for malformed JSON, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.wantReceived {
				if resp.ReceivedAt.IsZero() {
					t.Errorf("expected ReceivedAt to be non-zero, got zero value")
				}
			} else {
				if !resp.ReceivedAt.IsZero() {
					t.Errorf("expected ReceivedAt to be zero, got %v", resp.ReceivedAt)
				}
			}

			if tt.wantExactTime > 0 {
				got := resp.ReceivedAt.Unix()
				if got != tt.wantExactTime {
					t.Errorf("ReceivedAt.Unix() = %d, want %d", got, tt.wantExactTime)
				}
			}
		})
	}
}

// 无 received_at 字段时 ReceivedAt 接近 time.Now()
//
// 由于 time.Now() 在反序列化瞬间设置，校验 ReceivedAt 在 now±5s 范围内。
func TestBoundary_T16_UnmarshalJSON_NoReceivedAt_NearNow(t *testing.T) {
	before := time.Now()
	var resp IDaaSTokenResponse
	err := resp.UnmarshalJSON([]byte(`{"access_token":"abc","token_type":"Bearer","expires_in":3600}`))
	after := time.Now()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.ReceivedAt.IsZero() {
		t.Fatal("expected ReceivedAt to be non-zero (fallback to time.Now())")
	}
	if resp.ReceivedAt.Before(before) || resp.ReceivedAt.After(after.Add(time.Second)) {
		t.Errorf("ReceivedAt %v not within expected range [%v, %v]",
			resp.ReceivedAt, before, after.Add(time.Second))
	}
}

// received_at 为负数也走回退分支 (line 65)
func TestBoundary_T16_UnmarshalJSON_NegativeReceivedAt(t *testing.T) {
	var resp IDaaSTokenResponse
	err := resp.UnmarshalJSON([]byte(`{"access_token":"abc","token_type":"Bearer","expires_in":3600,"received_at":-100}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.ReceivedAt.IsZero() {
		t.Fatal("expected ReceivedAt to be non-zero for negative received_at (fallback to time.Now())")
	}
}

// ValidateLocalToken 在 UnmarshalJSON 后的集成校验
// 确保 UnmarshalJSON 不破坏 ValidateLocalToken 的逻辑。
func TestBoundary_T16_UnmarshalJSON_ThenValidate(t *testing.T) {
	tests := []struct {
		name      string
		raw       string
		wantValid bool
	}{
		{
			name:      "有效 Bearer token",
			raw:       `{"access_token":"abc","token_type":"Bearer","expires_in":3600}`,
			wantValid: true,
		},
		{
			name:      "空 access_token",
			raw:       `{"access_token":"","token_type":"Bearer","expires_in":3600}`,
			wantValid: false,
		},
		{
			name:      "非 Bearer token_type",
			raw:       `{"access_token":"abc","token_type":"MAC","expires_in":3600}`,
			wantValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var resp IDaaSTokenResponse
			if err := resp.UnmarshalJSON([]byte(tt.raw)); err != nil {
				t.Fatalf("unexpected unmarshal error: %v", err)
			}
			err := resp.ValidateLocalToken()
			if tt.wantValid && err != nil {
				t.Errorf("expected valid, got error: %v", err)
			}
			if !tt.wantValid && err == nil {
				t.Error("expected validation error, got nil")
			}
		})
	}
}

// 确保 UnmarshalJSON 后 String() 不 panic 且包含脱敏标记
func TestBoundary_T16_UnmarshalJSON_StringSafe(t *testing.T) {
	var resp IDaaSTokenResponse
	if err := resp.UnmarshalJSON([]byte(`{"access_token":"sensitive-token-value","token_type":"Bearer","expires_in":3600}`)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := resp.String()
	if !strings.HasPrefix(s, "IDaaSCredential{") {
		t.Errorf("String() should start with IDaaSCredential{, got: %s", s)
	}
	if strings.Contains(s, "sensitive-token-value") {
		t.Errorf("String() leaked raw token: %s", s)
	}
}
