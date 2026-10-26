package logger

import (
	"context"
	"strings"
	"sync"
	"testing"
)

// fakeToken 组装一个三段式 token 值(eyJ 起始),用于测试值形态脱敏。
// 用拼接构造,避免源码中出现字面量 token 被误判为泄露的真实凭证。
func fakeToken() string {
	return "eyJ" + "hbGciOiJSUzI1NiJ9" + "." + "eyJzdWIiOiJ0ZXN0In0" + "." + "signature1234567890abcdef"
}

// TestLooksLikeJWT 验证 F7 辅助函数:整串是 JWT 才命中,含 JWT 片段的较长文本不误伤。
func TestLooksLikeJWT(t *testing.T) {
	tok := fakeToken()
	tests := []struct {
		name string
		s    string
		want bool
	}{
		{"real token", tok, true},
		{"min token", "eyJ" + "hbGciOiJIUzI1NiJ9." + "eyJzdWIiOiJ4In0." + "sig1234567890", true},
		{"plain text", "hello world", false},
		{"empty", "", false},
		{"prefix but no dots", "eyJ" + "hbGciOiJIUzI1NiJ9", false},
		{"embedded in longer text", "error: " + tok + " occurred", false},
		{"in middle not at start", "prefix " + tok, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := looksLikeJWT(tc.s); got != tc.want {
				t.Errorf("looksLikeJWT(%q) = %v, want %v", tc.s, got, tc.want)
			}
		})
	}
}

// TestRedactKV_TokenValueUnderNonSensitiveKey 验证非敏感 key 下的 token 值被值形态兜底脱敏:
// 仅按 key 名脱敏会让凭证出现在 "debug_info"/"payload" 等非敏感 key 下时泄露。
func TestRedactKV_TokenValueUnderNonSensitiveKey(t *testing.T) {
	tok := fakeToken()
	kv := []interface{}{"debug_info", tok}
	got := RedactKV(kv)
	val, ok := got[1].(string)
	if !ok {
		t.Fatalf("value should be string, got %T", got[1])
	}
	if val == tok {
		t.Error("token value under non-sensitive key should be redacted, but leaked verbatim")
	}
	if !strings.HasPrefix(val, "eyJhbG") {
		t.Errorf("redacted value should retain 6-rune prefix, got %q", val)
	}
}

// TestRedactKV_NonTokenValueUnderNonSensitiveKey 非敏感 key + 非 token 字符串值应原样保留。
func TestRedactKV_NonTokenValueUnderNonSensitiveKey(t *testing.T) {
	kv := []interface{}{"endpoint", "https://api.example.com/token"}
	got := RedactKV(kv)
	if got[1] != "https://api.example.com/token" {
		t.Errorf("non-sensitive non-token value should be unchanged, got %v", got[1])
	}
}

// TestRedactKV_SensitiveKeyNotDoubleProcessed 敏感 key 已脱敏后,值形态 pass 不重复处理。
func TestRedactKV_SensitiveKeyNotDoubleProcessed(t *testing.T) {
	tok := fakeToken()
	kv := []interface{}{"access_token", tok}
	got := RedactKV(kv)
	val := got[1].(string)
	// 敏感 key 命中后已 Redact,值形态 pass 应 skip(continue),不二次处理。
	if !strings.Contains(val, "len=") {
		t.Errorf("sensitive key should be redacted once with len/sha256 metadata, got %q", val)
	}
}

// capturingLogger 记录 Info 调用的 msg,用于 F5 回归:断言 message 文本不被脱敏。
type capturingLogger struct {
	mu       sync.Mutex
	infoMsgs []string
}

func (c *capturingLogger) Debug(context.Context, string, ...interface{}) {}
func (c *capturingLogger) Info(_ context.Context, msg string, _ ...interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.infoMsgs = append(c.infoMsgs, msg)
}
func (c *capturingLogger) Warn(context.Context, string, ...interface{})  {}
func (c *capturingLogger) Error(context.Context, string, ...interface{}) {}

func (c *capturingLogger) Enabled(context.Context, Level) bool { return true }

func (c *capturingLogger) infoCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.infoMsgs)
}

// TestMessageTextNotRedacted 验证 F5 依赖的不变量:Logger.Info 的 message 文本
// 原样透传,RedactKV 只处理 kv 值、不触碰 message。
//
// device flow 在 verification_uri_complete 缺失时把一次性 user_code 拼进 message
// 让用户读取(RFC 8628)。若 message 也被脱敏,用户将无法完成授权。
// 这里用 capturing Logger 直接证明 message 不受脱敏影响。
func TestMessageTextNotRedacted(t *testing.T) {
	prev := Default()
	defer SetDefault(prev)

	capture := &capturingLogger{}
	SetDefault(capture)

	userCode := "ABCD-1234"
	// message 内嵌 user_code:必须原样可见。
	Default().Info(context.Background(), "enter this code in the verification page: "+userCode,
		"event", "human.device_code")

	if capture.infoCount() != 1 {
		t.Fatalf("expected 1 Info call captured, got %d", capture.infoCount())
	}
	if !strings.Contains(capture.infoMsgs[0], userCode) {
		t.Errorf("user_code in message must be visible (not redacted), got %q", capture.infoMsgs[0])
	}
}

// TestRedactKV_UserCodeAsKVValueIsRedacted 对照组:user_code 作为 kv 值时被脱敏,
// 印证 F5 必须把 code 放进 message 而非 kv 的设计动机。
func TestRedactKV_UserCodeAsKVValueIsRedacted(t *testing.T) {
	kv := []interface{}{"user_code", "ABCD-1234"}
	got := RedactKV(kv)
	val := got[1].(string)
	if strings.Contains(val, "ABCD-1234") {
		t.Errorf("user_code as kv value should be redacted, leaked %q", val)
	}
}
