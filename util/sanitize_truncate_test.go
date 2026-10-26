package util

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// TestSanitizeEndpointForLog 验证 endpoint 日志脱敏,剥离 userinfo/query/fragment,
// 仅保留 scheme://host/path,避免凭证(query 参数)或密码(userinfo)进入日志。
func TestSanitizeEndpointForLog(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"empty", "", ""},
		{"plain https", "https://api.example.com/oauth2/token", "https://api.example.com/oauth2/token"},
		{"strips userinfo credentials", "https://user:pass@api.example.com/token", "https://api.example.com/token"},
		{"strips query string", "https://api.example.com/token?client_id=xxx&secret=yyy", "https://api.example.com/token"},
		{"strips fragment", "https://api.example.com/token#section", "https://api.example.com/token"},
		{"keeps port", "https://api.example.com:8443/token", "https://api.example.com:8443/token"},
		{"http scheme preserved", "http://localhost:8080/auth", "http://localhost:8080/auth"},
		{"unparseable", "://not a valid url", "<unparseable>"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := SanitizeEndpointForLog(tc.input)
			if got != tc.expected {
				t.Errorf("SanitizeEndpointForLog(%q) = %q, want %q", tc.input, got, tc.expected)
			}
		})
	}
}

// TestSanitizeEndpointForLog_NoCredentialLeak 断言敏感片段绝不出现在脱敏结果中。
func TestSanitizeEndpointForLog_NoCredentialLeak(t *testing.T) {
	raw := "https://client_id:super-secret-token@api.example.com/token?refresh_token=abc123&code=xyz"
	got := SanitizeEndpointForLog(raw)
	for _, leak := range []string{"super-secret-token", "abc123", "xyz", "client_id", "refresh_token"} {
		if strings.Contains(got, leak) {
			t.Errorf("sanitized endpoint leaked %q: %q", leak, got)
		}
	}
}

// TestTruncateForError_UTF8Boundary 验证截断回退到完整 UTF-8 码点边界,
// 不切出半个多字节字符产生非法 UTF-8 字符串。
func TestTruncateForError_UTF8Boundary(t *testing.T) {
	// "é" 是 2 字节 (0xC3 0xA9)。5 个 ASCII 'x' + 100 个 "é" = 205 字节。
	// max=6 落在第一个 "é" 的续续字节 0xA9 上,必须回退到 0xC3 的前一个完整码点。
	b := []byte("xxxxx" + strings.Repeat("é", 100))
	got := TruncateForError(b, 6)
	if !utf8.ValidString(got) {
		t.Errorf("truncated result is not valid UTF-8: %q", got)
	}
	// 回退后应只剩 5 个 'x'(整段 "é" 被丢弃,因为切点落在其内部)。
	if !strings.HasPrefix(got, "xxxxx") {
		t.Errorf("expected ASCII prefix preserved, got %q", got)
	}
	if !strings.Contains(got, "(truncated)") {
		t.Errorf("expected truncation marker, got %q", got)
	}
	// 关键回归:结果绝不能包含半个 "é" (裸 0xC3 字节)。
	if strings.Contains(got, "\xc3") {
		t.Errorf("truncation produced a half-rune (0xC3): %q", got)
	}
}

// TestTruncateForError_3ByteRuneBoundary 中文字符(3 字节)截断落在续续字节上。
func TestTruncateForError_3ByteRuneBoundary(t *testing.T) {
	// "中" 是 3 字节 (E4 B8 AD)。200 个 "中" = 600 字节。max=512 落在第 171 个
	// "中" 的第 2 字节 B8(续续字节)上,必须回退到 510(170 个完整 "中")。
	b := []byte(strings.Repeat("中", 200))
	got := TruncateForError(b, 512)
	if !utf8.ValidString(got) {
		t.Errorf("truncated result is not valid UTF-8")
	}
	if !strings.HasSuffix(got, "...(truncated)") {
		t.Errorf("expected truncation marker, got suffix of %q", got[len(got)-30:])
	}
}

// TestTruncateForError_WithinLimit 不超过 max 时原样返回。
func TestTruncateForError_WithinLimit(t *testing.T) {
	got := TruncateForError([]byte("short"), 512)
	if got != "short" {
		t.Errorf("expected original short string, got %q", got)
	}
}

// TestTruncateForError_NonPositiveMaxDefaultsTo512 max<=0 时回退到 512 默认值。
func TestTruncateForError_NonPositiveMaxDefaultsTo512(t *testing.T) {
	long := strings.Repeat("A", 600)
	got := TruncateForError([]byte(long), 0)
	if !strings.Contains(got, "(truncated)") {
		t.Errorf("max=0 should default to 512 and truncate, got len=%d", len(got))
	}
	got2 := TruncateForError([]byte(long), -1)
	if !strings.Contains(got2, "(truncated)") {
		t.Errorf("max<0 should default to 512 and truncate, got len=%d", len(got2))
	}
}
