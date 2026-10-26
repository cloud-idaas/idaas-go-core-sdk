package oauth2

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/cloud-idaas/idaas-go-core-sdk/constants"
	"github.com/cloud-idaas/idaas-go-core-sdk/domain"
	sdkerrors "github.com/cloud-idaas/idaas-go-core-sdk/errors"
)

// ValidateLocalToken 在 200 响应但令牌无效时失败
//
// postFormWithHeadersWithContext 在 HTTP 200 响应反序列化成功后会调用
// IDaaSTokenResponse.ValidateLocalToken。当 access_token
// 为空或 token_type 不是 Bearer 时应分别返回对应的 CredentialError。
func TestBoundary_T14_ValidateLocalToken_InvalidToken(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		wantCode    string
		wantMsgPart string
	}{
		{
			name:        "200 响应 access_token 为空",
			body:        `{"access_token":"","token_type":"Bearer","expires_in":3600}`,
			wantCode:    constants.AccessTokenNotFound,
			wantMsgPart: "access_token",
		},
		{
			name:        "200 响应 token_type 非 Bearer",
			body:        `{"access_token":"abc","token_type":"MAC","expires_in":3600}`,
			wantCode:    constants.InvalidTokenType,
			wantMsgPart: "Bearer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockHttpClient{
				Response: &domain.HttpResponse{
					StatusCode: http.StatusOK,
					Headers:    map[string][]string{"Content-Type": {"application/json"}},
					Body:       []byte(tt.body),
				},
			}
			util := NewOAuth2TokenUtil(mockClient)

			_, err := util.postFormWithHeadersForTokenResponseWithContext(
				context.Background(),
				"https://example.com/oauth/token", "k=v", nil,
			)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !sdkerrors.HasCode(err, tt.wantCode) {
				t.Errorf("error code = %q, want %q; err=%v", errorCodeOf(err), tt.wantCode, err)
			}
			if !strings.Contains(err.Error(), tt.wantMsgPart) {
				t.Errorf("error message should contain %q, got: %s", tt.wantMsgPart, err.Error())
			}
		})
	}
}

// extraHeaders 含 Content-Type 时 continue 跳过
//
// postFormWithHeadersWithContext 在遍历 extraHeaders 时
// 会跳过 "Content-Type" 键，保证内部设置的 form-urlencoded Content-Type 不被覆盖。
// 本测试通过 headerCapturingClient 捕获最终发出的请求 header，验证：
//   - Content-Type 始终为 application/x-www-form-urlencoded（不被 extraHeaders 覆盖）
//   - 其余自定义 header 正常透传
func TestBoundary_T15_ExtraHeadersContentTypeSkipped(t *testing.T) {
	tests := []struct {
		name         string
		extraHeaders map[string]string
		wantCT       string
		wantCustom   string // 期望透传的自定义 header 值（空串表示不校验）
	}{
		{
			name: "extraHeaders 含 Content-Type 应被忽略",
			extraHeaders: map[string]string{
				"Content-Type": "application/json", // 应被 continue 跳过
				"X-Trace":      "val1",
			},
			wantCT:     constants.ContentTypeFormUrlEncoded,
			wantCustom: "val1",
		},
		{
			name:         "extraHeaders 为 nil",
			extraHeaders: nil,
			wantCT:       constants.ContentTypeFormUrlEncoded,
			wantCustom:   "",
		},
		{
			name: "extraHeaders 仅含普通自定义 header",
			extraHeaders: map[string]string{
				"Authorization": "Basic dGVzdDp0ZXN0",
				"X-Trace":       "abc",
			},
			wantCT:     constants.ContentTypeFormUrlEncoded,
			wantCustom: "abc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var captured *domain.HttpRequest
			mockClient := &headerCapturingClient{
				response: createSuccessTokenResponse(t),
				onCall: func(req *domain.HttpRequest) {
					captured = req
				},
			}
			util := NewOAuth2TokenUtil(mockClient)

			_, err := util.postFormWithHeadersForTokenResponseWithContext(
				context.Background(),
				"https://example.com/oauth/token", "k=v", tt.extraHeaders,
			)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if captured == nil {
				t.Fatal("expected captured request, got nil")
			}
			// Content-Type 必须始终是 form-urlencoded，不被 extraHeaders 覆盖
			gotCT, ok := captured.Headers[constants.HeaderContentType]
			if !ok {
				t.Fatalf("expected %s header to be set", constants.HeaderContentType)
			}
			if gotCT != tt.wantCT {
				t.Errorf("Content-Type = %q, want %q", gotCT, tt.wantCT)
			}
			// 自定义 header 应正常透传
			if tt.wantCustom != "" {
				gotCustom, ok := captured.Headers["X-Trace"]
				if !ok || gotCustom != tt.wantCustom {
					t.Errorf("X-Trace header not propagated correctly, got: %q, want %q", gotCustom, tt.wantCustom)
				}
			}
		})
	}
}

// errorCodeOf 从 error 链上提取第一个非空的 ErrorCode。
func errorCodeOf(err error) string {
	if idaasErr, ok := sdkerrors.AsIDaaSError(err); ok && idaasErr != nil {
		return idaasErr.ErrorCode()
	}
	if ie, ok := err.(interface{ ErrorCode() string }); ok {
		return ie.ErrorCode()
	}
	return ""
}
