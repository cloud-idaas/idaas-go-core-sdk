package credential

import (
	"strings"
	"testing"
)

// TestIDaaSTokenResponse_String_SanitizeControlChars 验证 sanitizeForLog 的所有
// 控制字符分支(\n/\r/\t/C0 控制字符/0x7f),防止服务端响应中的控制字符伪造额外
// 日志行(log injection)。通过 String() 间接覆盖。
func TestIDaaSTokenResponse_String_SanitizeControlChars(t *testing.T) {
	r := &IDaaSTokenResponse{
		// TokenType 含全部需转义的控制字符:换行、回车、制表符、C0 控制字符、DEL(0x7f)。
		TokenType: "Bear\ner\r\n\ttab\x01ctrl\x7fdel",
		ExpiresIn: 3600,
		Scope:     "api|read",
	}
	out := r.String()

	// 转义形式应出现在输出中。
	for _, esc := range []string{`\n`, `\r`, `\t`} {
		if !strings.Contains(out, esc) {
			t.Errorf("expected escape %q in String() output, got %q", esc, out)
		}
	}
	// C0 控制字符与 DEL 应被替换为 '?',原始裸控制字符不得残留。
	for _, raw := range []string{"\x01", "\x7f", "\n", "\r", "\t"} {
		if strings.Contains(out, raw) {
			t.Errorf("raw control char leaked into String() output: %q", out)
		}
	}
	// 正常 rune 保留。
	if !strings.Contains(out, "Bear") {
		t.Errorf("expected normal text preserved, got %q", out)
	}
}

// TestIDaaSTokenResponse_String_EmptyTokenTypeSanitized 空字段不 panic,sanitizeForLog("") 走空串分支。
func TestIDaaSTokenResponse_String_EmptyTokenTypeSanitized(t *testing.T) {
	r := &IDaaSTokenResponse{ExpiresIn: 60}
	out := r.String()
	if !strings.Contains(out, "IDaaSCredential{") {
		t.Errorf("expected String() prefix, got %q", out)
	}
}
