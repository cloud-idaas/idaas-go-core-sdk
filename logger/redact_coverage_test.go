package logger

import (
	"net/url"
	"strings"
	"testing"
)

// TestRedact_Empty 空串原样返回。
func TestRedact_Empty(t *testing.T) {
	if got := Redact(""); got != "" {
		t.Errorf("Redact(\"\") = %q, want empty", got)
	}
}

// TestRedact_ShortString 短于 6 字符的字符串不暴露任何明文前缀,也不暴露 sha256 摘要。
// 短 keyspace 值的 32-bit sha256 可被暴力枚举还原,不应输出。
func TestRedact_ShortString(t *testing.T) {
	got := Redact("abc")
	// 短值不保留任何明文前缀，避免泄露密码等短敏感值
	if strings.Contains(got, "abc") {
		t.Errorf("Redact(\"abc\") = %q, should not contain full plaintext", got)
	}
	if !strings.Contains(got, "len=3") {
		t.Errorf("Redact(\"abc\") = %q, should contain len=3", got)
	}
	if strings.Contains(got, "sha256=") {
		t.Errorf("Redact(\"abc\") = %q, short value must not expose sha256 (brute-forceable)", got)
	}
}

// TestRedact_LongString 长字符串截取前 6 字符。
func TestRedact_LongString(t *testing.T) {
	s := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature"
	got := Redact(s)
	if !strings.HasPrefix(got, "eyJhbG") {
		t.Errorf("Redact long string = %q, should start with first 6 chars", got)
	}
	if !strings.Contains(got, "len=") {
		t.Errorf("Redact = %q, should contain len", got)
	}
	// 确保原文完整内容不出现
	if strings.Contains(got, "payload.signature") {
		t.Errorf("Redact = %q, should not contain full original string", got)
	}
}

// TestRedact_ExactSixChars 刚好 6 字符也不暴露明文前缀。
func TestRedact_ExactSixChars(t *testing.T) {
	s := "abcdef"
	got := Redact(s)
	// 长度等于 redactPrefixLen 时同样不保留前缀
	if strings.Contains(got, "abcdef") {
		t.Errorf("Redact = %q, should not contain full 6-char plaintext", got)
	}
	if !strings.Contains(got, "len=6") {
		t.Errorf("Redact = %q, should contain len=6", got)
	}
}

// TestRedact_MultibyteString 多字节字符的截取按 rune 计。
func TestRedact_MultibyteString(t *testing.T) {
	// 8 个中文字符，每个 3 字节
	s := "中文测试字符串啊"
	got := Redact(s)
	// prefix 应是前 6 个 rune
	if !strings.HasPrefix(got, "中文测试字符") {
		t.Errorf("Redact multibyte = %q, should start with first 6 runes", got)
	}
}

// TestRedact_Deterministic 同一输入两次调用结果应一致。
func TestRedact_Deterministic(t *testing.T) {
	s := "secret-token-value-12345"
	got1 := Redact(s)
	got2 := Redact(s)
	if got1 != got2 {
		t.Errorf("Redact is not deterministic: %q != %q", got1, got2)
	}
}

// TestRedact_DifferentInputsDifferentHash 不同输入的 sha256 应不同。
func TestRedact_DifferentInputsDifferentHash(t *testing.T) {
	got1 := Redact("input-one")
	got2 := Redact("input-two")
	if got1 == got2 {
		t.Error("Redact should produce different outputs for different inputs")
	}
}

// TestRedact_Format 包含所有组成部分。
func TestRedact_Format(t *testing.T) {
	s := "ABCDEFGHIJKLMNOP"
	got := Redact(s)
	if !strings.Contains(got, "***(len=") {
		t.Errorf("Redact = %q, should contain ***(len=", got)
	}
	if !strings.Contains(got, ",sha256=") {
		t.Errorf("Redact = %q, should contain ,sha256=", got)
	}
	if !strings.HasSuffix(got, ")") {
		t.Errorf("Redact = %q, should end with )", got)
	}
}

func TestIsSensitiveKey(t *testing.T) {
	tests := []struct {
		name string
		key  string
		want bool
	}{
		// 命中
		{"accesstoken", "access_token", true},
		{"accessToken camel", "accessToken", true},
		{"access-token dash", "access-token", true},
		{"ACCESS_TOKEN upper", "ACCESS_TOKEN", true},
		{"access.token dot", "access.token", true},
		{"access token space", "access token", true},
		{"idtoken", "id_token", true},
		{"refreshtoken", "refresh_token", true},
		{"subjecttoken", "subject_token", true},
		{"actortoken", "actor_token", true},
		{"clientsecret", "client_secret", true},
		{"clientassertion", "client_assertion", true},
		{"privatekey", "private_key", true},
		{"secret", "secret", true},
		{"password", "password", true},
		{"authorization", "Authorization", true},
		{"credential", "credential", true},
		{"devicecode", "device_code", true},
		{"usercode", "user_code", true},
		{"code", "code", true},
		{"token", "token", true},
		// 不命中
		{"hostname", "hostname", false},
		{"endpoint", "endpoint", false},
		{"timeout", "timeout", false},
		{"method", "method", false},
		{"empty", "", false},
		{"user-agent", "user_agent", false},
		{"client_id", "client_id", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsSensitiveKey(tt.key); got != tt.want {
				t.Errorf("IsSensitiveKey(%q) = %v, want %v", tt.key, got, tt.want)
			}
		})
	}
}

// TestRedactKV_NoSensitiveKeys 无敏感 key 时不变。
func TestRedactKV_NoSensitiveKeys(t *testing.T) {
	kv := []interface{}{"endpoint", "https://api.example.com", "method", "POST"}
	got := RedactKV(kv)
	if got[1] != "https://api.example.com" {
		t.Errorf("RedactKV should not modify non-sensitive values")
	}
	if got[3] != "POST" {
		t.Errorf("RedactKV should not modify non-sensitive values")
	}
}

// TestRedactKV_SensitiveString 敏感 key + string value → Redact。
func TestRedactKV_SensitiveString(t *testing.T) {
	kv := []interface{}{"access_token", "eyJhbGciOiJSUzI1NiJ9.secret"}
	got := RedactKV(kv)
	val, ok := got[1].(string)
	if !ok {
		t.Fatalf("RedactKV value should be string, got %T", got[1])
	}
	if val == "eyJhbGciOiJSUzI1NiJ9.secret" {
		t.Error("RedactKV should redact sensitive string value")
	}
	if !strings.HasPrefix(val, "eyJhbG") {
		t.Errorf("RedactKV redacted value should start with prefix, got %q", val)
	}
}

// TestRedactKV_SensitiveStringer 敏感 key + Stringer value → Redact。
func TestRedactKV_SensitiveStringer(t *testing.T) {
	kv := []interface{}{"client_secret", stringerVal("super-secret-value")}
	got := RedactKV(kv)
	val, ok := got[1].(string)
	if !ok {
		t.Fatalf("RedactKV value should be string, got %T", got[1])
	}
	if val == "super-secret-value" {
		t.Error("RedactKV should redact Stringer value")
	}
	if !strings.Contains(val, "sha256=") {
		t.Errorf("RedactKV redacted Stringer value should contain sha256, got %q", val)
	}
}

// TestRedactKV_SensitiveNil 敏感 key + nil value → 保持 nil。
func TestRedactKV_SensitiveNil(t *testing.T) {
	kv := []interface{}{"access_token", nil}
	got := RedactKV(kv)
	if got[1] != nil {
		t.Errorf("RedactKV should keep nil as nil, got %v", got[1])
	}
}

// TestRedactKV_SensitiveNonString 敏感 key + 非 string/Stringer value → ***.
func TestRedactKV_SensitiveNonString(t *testing.T) {
	kv := []interface{}{"token", 12345}
	got := RedactKV(kv)
	if got[1] != "***" {
		t.Errorf("RedactKV should replace non-string sensitive value with ***, got %v", got[1])
	}
}

// TestRedactKV_OddLength 奇数长度先归一化再脱敏。
func TestRedactKV_OddLength(t *testing.T) {
	kv := []interface{}{"access_token", "secret", "orphan"}
	got := RedactKV(kv)
	// 归一化后: BADKEY, "orphan" → orphan 不敏感, 不脱敏
	// access_token 的值应被脱敏
	val, ok := got[1].(string)
	if !ok {
		t.Fatalf("RedactKV value should be string, got %T", got[1])
	}
	if val == "secret" {
		t.Error("RedactKV should redact sensitive value even with odd-length kv")
	}
}

// TestRedactKV_NonStringKey 非 string key 先补 BADKEY。
func TestRedactKV_NonStringKey(t *testing.T) {
	kv := []interface{}{42, "val"}
	got := RedactKV(kv)
	// 归一化: BADKEY, 42, BADKEY, "val"
	// BADKEY 不敏感
	if got[3] != "val" {
		t.Errorf("RedactKV should not redact value under non-sensitive key, got %v", got[3])
	}
}

// TestRedactKV_MultipleSensitive 多个敏感 key。
func TestRedactKV_MultipleSensitive(t *testing.T) {
	kv := []interface{}{
		"access_token", "token-value-1",
		"refresh_token", "token-value-2",
		"client_secret", "secret1",
	}
	got := RedactKV(kv)
	for i := 1; i < len(got); i += 2 {
		val, ok := got[i].(string)
		if !ok {
			t.Errorf("RedactKV[%d] should be string, got %T", i, got[i])
			continue
		}
		if !strings.Contains(val, "***") {
			t.Errorf("RedactKV[%d] should be redacted, got %q", i, val)
		}
	}
}

// TestRedactKV_Empty 空输入。
func TestRedactKV_Empty(t *testing.T) {
	got := RedactKV(nil)
	if len(got) != 0 {
		t.Errorf("RedactKV(nil) should return empty slice, got %v", got)
	}
}

// stringerVal 实现 fmt.Stringer。
type stringerVal string

func (s stringerVal) String() string {
	return string(s)
}

// TestRedact_ShortValueNoPlaintext 短值（len <= redactPrefixLen）不暴露任何明文,
// 也不暴露 sha256 摘要(短 keyspace 的 32-bit hash 可暴力还原)。
func TestRedact_ShortValueNoPlaintext(t *testing.T) {
	tests := []struct {
		name string
		val  string
	}{
		{"2 chars", "ab"},
		{"3 chars", "abc"},
		{"5 chars", "abc12"},
		{"exactly 6", "abc123"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Redact(tt.val)
			if strings.Contains(got, tt.val) {
				t.Errorf("Redact(%q) = %q, must not contain full plaintext", tt.val, got)
			}
			if !strings.Contains(got, "len=") {
				t.Errorf("Redact(%q) = %q, should contain len", tt.val, got)
			}
			if strings.Contains(got, "sha256=") {
				t.Errorf("Redact(%q) = %q, short value must not expose sha256", tt.val, got)
			}
		})
	}
}

// TestRedactKV_ShortPasswordNoPlaintext 敏感 key + 短 string value 不暴露明文,也不暴露 sha256。
func TestRedactKV_ShortPasswordNoPlaintext(t *testing.T) {
	kv := []interface{}{"password", "abc123"}
	got := RedactKV(kv)
	val, ok := got[1].(string)
	if !ok {
		t.Fatalf("RedactKV value should be string, got %T", got[1])
	}
	if strings.Contains(val, "abc123") {
		t.Errorf("RedactKV should not expose full plaintext for short password, got %q", val)
	}
	if strings.Contains(val, "sha256=") {
		t.Errorf("RedactKV short value must not expose sha256, got %q", val)
	}
}

// TestRedactKV_TypedNilStringerDoesNotPanic typed-nil 指针匹配 Stringer case 不 panic。
func TestRedactKV_TypedNilStringerDoesNotPanic(t *testing.T) {
	// (*url.URL)(nil) 实现了 String() string，但 receiver 为 nil 时调用会 panic。
	// RedactKV 必须检测 typed-nil 并输出占位符，而非调用 String()。
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("RedactKV panicked on typed-nil Stringer: %v", r)
		}
	}()

	kv := []interface{}{"token", (*url.URL)(nil)}
	got := RedactKV(kv)
	if got[1] != "<nil>" {
		t.Errorf("RedactKV typed-nil Stringer = %v, want \"<nil>\"", got[1])
	}
}
