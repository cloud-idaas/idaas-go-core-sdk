package oauth2

import (
	"errors"
	"strings"
	"testing"

	"github.com/cloud-idaas/idaas-go-core-sdk/domain"
	sdkerrors "github.com/cloud-idaas/idaas-go-core-sdk/errors"
)

func prefixLen(s string, n int) string {
	if len(s) < n {
		return s
	}
	return s[:n]
}

// 非 OAuth2 标准错误的原始 body 必须被截断后再拼进 error message,
// 避免恶意/故障 IdP 返回超大 body 撑爆日志与错误链。
// 的 TruncateForError 只覆盖了 attestation provider;主 token 端点错误路径
// (parseOAuth2Error 的非 JSON 分支)也要截断。
func TestParseOAuth2Error_NonOAuthBody_Truncated(t *testing.T) {
	huge := strings.Repeat("X", 8192) // 8 KiB,远超 512 截断阈值
	resp := &domain.HttpResponse{
		StatusCode: 400,
		Body:       []byte(huge),
	}
	err := parseOAuth2Error(resp)
	if err == nil {
		t.Fatal("expected error for non-OAuth2 4xx response")
	}
	msg := err.Error()
	// 截断后 message 长度应远小于原始 8 KiB(允许 "...(truncated)" 后缀 + 状态码前缀)。
	if len(msg) > 600 {
		t.Errorf("error message not truncated: len=%d (want <= ~600). msg prefix=%q",
			len(msg), prefixLen(msg, 120))
	}
	if !strings.Contains(msg, "(truncated)") {
		t.Errorf("expected truncation marker in message, got: %q", prefixLen(msg, 120))
	}
}

// OAuth2 标准错误体被正确解析后,RawBody 字段也应存截断版本,不保留整段原文。
// 注意:的范围是 raw body(非结构化字段),不包含已解析的 error_description
// (结构化字段,截断会丢失语义,见 v5 报告说明)。因此本测试只断言 RawBody。
func TestParseOAuth2Error_OAuthBody_RawBodyTruncated(t *testing.T) {
	oauthBody := `{"error":"invalid_grant","error_description":"` + strings.Repeat("Y", 8192) + `"}`
	resp := &domain.HttpResponse{
		StatusCode: 400,
		Body:       []byte(oauthBody),
	}
	err := parseOAuth2Error(resp)
	if err == nil {
		t.Fatal("expected OAuth2Error")
	}
	var oauth2Err *sdkerrors.OAuth2Error
	if !errors.As(err, &oauth2Err) {
		t.Fatalf("expected *OAuth2Error, got %T: %v", err, err)
	}
	// RawBody 应被截断到 ~512 字节(允许 "(truncated)" 后缀)。
	if len(oauth2Err.RawBody) > 600 {
		t.Errorf("RawBody not truncated: len=%d (want <= ~600). RawBody prefix=%q",
			len(oauth2Err.RawBody), prefixLen(oauth2Err.RawBody, 120))
	}
	if !strings.Contains(oauth2Err.RawBody, "(truncated)") {
		t.Errorf("expected truncation marker in RawBody, got: %q", prefixLen(oauth2Err.RawBody, 120))
	}
}
