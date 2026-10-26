package errors

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// fakeToken 组装一个三段式 token(eyJ 起始),用拼接避免源码出现字面量凭证。
func fakeToken() string {
	return "eyJ" + "hbGciOiJSUzI1NiJ9" + "." + "eyJzdWIiOiJ0ZXN0In0" + "." + "signature1234567890abcdef"
}

// TestRedactDescription_TokenReplaced error_description 中嵌入的完整 token 被替换为 ***。
// 短 token(< 512 字节)若不脱敏会被完整回显在 Error() 中。
func TestRedactDescription_TokenReplaced(t *testing.T) {
	tok := fakeToken()
	desc := "server side error: token=" + tok + " more text"
	got := RedactDescription(desc)
	if strings.Contains(got, tok) {
		t.Errorf("token should be redacted, leaked in %q", got)
	}
	if !strings.Contains(got, "***") {
		t.Errorf("expected *** placeholder after redaction, got %q", got)
	}
}

// TestRedactDescription_SensitiveParamReplaced refresh_token 等敏感参数赋值的值被替换。
func TestRedactDescription_SensitiveParamReplaced(t *testing.T) {
	cases := []string{
		"refresh_token=secretvalue123 more",
		"access_token:secretvalue123 end",
		"client_secret = secretvalue123",
	}
	for _, desc := range cases {
		got := RedactDescription(desc)
		if strings.Contains(got, "secretvalue123") {
			t.Errorf("sensitive param value should be redacted for %q, got %q", desc, got)
		}
		if !strings.Contains(got, "***") {
			t.Errorf("expected *** placeholder for %q, got %q", desc, got)
		}
	}
}

// TestRedactDescription_PlainTextUnchanged 无敏感内容的普通文本原样返回。
func TestRedactDescription_PlainTextUnchanged(t *testing.T) {
	desc := "the provided grant is invalid or expired"
	if got := RedactDescription(desc); got != desc {
		t.Errorf("plain text should pass through unchanged, got %q", got)
	}
}

// TestOAuth2Error_Error_DescriptionWithTokenRedacted Error() 输出不含原始 token。
func TestOAuth2Error_Error_DescriptionWithTokenRedacted(t *testing.T) {
	tok := fakeToken()
	err := NewOAuth2Error(400, "invalid_grant", "bad token: "+tok, "", nil)
	msg := err.Error()
	if strings.Contains(msg, tok) {
		t.Errorf("Error() must not leak token, got %q", msg)
	}
	if !strings.Contains(msg, "***") {
		t.Errorf("Error() should contain redaction placeholder, got %q", msg)
	}
	// FullDescription 仍保留完整原文(供 errors.As 后结构化排查)。
	if got := err.FullDescription(); !strings.Contains(got, tok) {
		t.Errorf("FullDescription() should retain original token for debugging, got %q", got)
	}
}

// TestTruncateForLog_UTF8Boundary 验证截断回退到码点边界,不产生非法 UTF-8。
// 通过 Error() 间接测 truncateForLog:error_description 用多字节字符(中文,3 字节)
// 填充到超过 512 字节,切点落在续续字节上必须回退。
func TestTruncateForLog_UTF8Boundary(t *testing.T) {
	// 200 个 "中" = 600 字节,超过 512。512 落在第 171 个 "中" 的第 2 字节(续续字节)。
	desc := strings.Repeat("中", 200)
	err := NewOAuth2Error(500, "server_error", desc, "", nil)
	msg := err.Error()
	if !utf8.ValidString(msg) {
		t.Errorf("Error() produced invalid UTF-8 after truncation")
	}
	if !strings.Contains(msg, "(truncated)") {
		t.Errorf("expected truncation marker, got suffix %q", msg[len(msg)-30:])
	}
	if !strings.Contains(msg, "server_error") {
		t.Errorf("expected OAuth code in message, got %q", msg)
	}
	// 完整原文仍可通过 FullDescription 取得。
	if got := err.FullDescription(); len(got) != 600 {
		t.Errorf("FullDescription should be full 600 bytes, got %d", len(got))
	}
}

// TestRedactDescription_Idempotent 两次脱敏结果一致。
func TestRedactDescription_Idempotent(t *testing.T) {
	tok := fakeToken()
	desc := "refresh_token=" + tok
	first := RedactDescription(desc)
	second := RedactDescription(first)
	if first != second {
		t.Errorf("RedactDescription not idempotent:\n first=%q\nsecond=%q", first, second)
	}
}
