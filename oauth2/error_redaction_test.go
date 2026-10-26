package oauth2

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/cloud-idaas/idaas-go-core-sdk/domain"
	sdkerrors "github.com/cloud-idaas/idaas-go-core-sdk/errors"
)

// fakeToken 组装一个三段式 token(eyJ 起始),用拼接避免源码出现字面量凭证。
func fakeToken() string {
	return "eyJ" + "hbGciOiJSUzI1NiJ9" + "." + "eyJzdWIiOiJ0ZXN0In0" + "." + "signature1234567890abcdef"
}

// TestParseOAuth2Error_5xxOAuthBody_DescriptionRedacted 验证 5xx 响应的
// error_description 被拼进 ServerError.Message 前必须经 errors.RedactDescription 脱敏,
// 与 4xx OAuth2Error.Error() 对称:否则 IdP 回显的 refresh_token / token
// 会泄露进日志与 err.Error()。
func TestParseOAuth2Error_5xxOAuthBody_DescriptionRedacted(t *testing.T) {
	tok := fakeToken()
	// error_description 含敏感参数赋值 + 完整 token,长度 < 512(不会被长度截断抹掉)。
	oauthBody := `{"error":"server_error","error_description":"refresh_token=` + tok + `"}`
	resp := &domain.HttpResponse{
		StatusCode: 503,
		Body:       []byte(oauthBody),
	}
	err := parseOAuth2Error(resp)
	if err == nil {
		t.Fatal("expected error for 5xx OAuth2 response")
	}

	// 5xx 应返回 *ServerError,Cause 为解析出的 *OAuth2Error。
	var serverErr *sdkerrors.ServerError
	if !errors.As(err, &serverErr) {
		t.Fatalf("expected *ServerError, got %T: %v", err, err)
	}

	// ServerError.Message 绝不含原始 token / refresh_token 值。
	if strings.Contains(serverErr.Message, tok) {
		t.Errorf("token leaked into ServerError.Message: %q", serverErr.Message)
	}
	if !strings.Contains(serverErr.Message, "***") {
		t.Errorf("expected redaction placeholder in Message, got: %q", serverErr.Message)
	}

	// 完整原文仍可通过 Cause 链 *OAuth2Error.FullDescription() 取得(errors.As)。
	var oauth2Err *sdkerrors.OAuth2Error
	if !errors.As(err, &oauth2Err) {
		t.Fatalf("expected underlying *OAuth2Error as Cause, got %T", err)
	}
	if !strings.Contains(oauth2Err.FullDescription(), tok) {
		t.Errorf("FullDescription should retain original token for debugging, got: %q",
			oauth2Err.FullDescription())
	}
}

// TestParseOAuth2Error_5xxOAuthBody_LongDescriptionTruncated 5xx 超长 description
// 既脱敏又截断。
func TestParseOAuth2Error_5xxOAuthBody_LongDescriptionTruncated(t *testing.T) {
	longDesc := "refresh_token=" + strings.Repeat("Z", 8192)
	oauthBody := `{"error":"server_error","error_description":"` + longDesc + `"}`
	resp := &domain.HttpResponse{
		StatusCode: 500,
		Body:       []byte(oauthBody),
	}
	err := parseOAuth2Error(resp)
	var serverErr *sdkerrors.ServerError
	if !errors.As(err, &serverErr) {
		t.Fatalf("expected *ServerError, got %T", err)
	}
	// 脱敏 + 截断后 Message 远小于 8 KiB,且含脱敏占位符。
	if len(serverErr.Message) > 700 {
		t.Errorf("Message not truncated: len=%d", len(serverErr.Message))
	}
	if !strings.Contains(serverErr.Message, "***") {
		t.Errorf("expected redaction placeholder in Message, got: %q", serverErr.Message)
	}
}

// TestParseOAuth2Error_NonStandardBody_Redacted 验证非标准响应体(body 非 OAuth2
// JSON 或无 error 字段)拼入 HttpError.Message 前必须经 errors.RedactDescription
// 脱敏,与 5xx 标准 OAuth2 路径对称。否则 IdP 在非标准错误体(网关 HTML、非标
// JSON)中回显的 refresh_token / client_secret(opaque 非 JWT 形态)会绕过
// jwtPattern 兜底,经 err.Error() → 异步刷新失败日志(cached_result_supplier
// "error", err.Error())明文泄露。
func TestParseOAuth2Error_NonStandardBody_Redacted(t *testing.T) {
	// opaque(非 eyJ 起始)token:仅 sensitiveValuePattern 的 refresh_token= 分支
	// 能脱敏,jwtPattern 不会命中,用以验证 RedactDescription 真正覆盖此分支。
	opaqueTok := "opaque_secret_0xAB12cd"

	cases := []struct {
		name   string
		status int
	}{
		{"4xx non-json", http.StatusForbidden},
		{"5xx non-json", http.StatusBadGateway},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := `<html>refresh_token=` + opaqueTok + `</html>`
			err := parseOAuth2Error(&domain.HttpResponse{
				StatusCode: tc.status,
				Headers:    map[string][]string{},
				Body:       []byte(body),
			})
			if err == nil {
				t.Fatal("expected error for non-standard response")
			}

			// err.Error() 是异步刷新失败日志 "error", err.Error() 的实际泄露面:
			// 4xx 直接返回 *HttpError;5xx 经 *ServerError 包装,Cause 链上的
			// *HttpError.Message(含已脱敏 body)经 %v 流入 ServerError.Error()。
			if strings.Contains(err.Error(), opaqueTok) {
				t.Errorf("opaque token leaked into err.Error(): %q", err.Error())
			}
			if !strings.Contains(err.Error(), "***") {
				t.Errorf("expected redaction placeholder in err.Error(), got: %q", err.Error())
			}

			// 非标准分支不得误判为 OAuth2Error。
			var oauth2Err *sdkerrors.OAuth2Error
			if errors.As(err, &oauth2Err) {
				t.Errorf("non-standard body must not parse as *OAuth2Error, got: %v", oauth2Err)
			}
		})
	}
}
