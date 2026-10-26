package authentication

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/cloud-idaas/idaas-go-core-sdk/credential"
	"github.com/cloud-idaas/idaas-go-core-sdk/domain"
	sdkerrors "github.com/cloud-idaas/idaas-go-core-sdk/errors"
)

// isRefreshGrantRequest 判断 form 请求体是否为 refresh_token grant。
// grant_type=refresh_token 与 device_code 轮询(urn:ietf:params:oauth:grant-type:device_code)
// 都打到 tokenEndpoint,需用 body 区分以精确路由 mock。
// HttpRequest.Body 是 interface{},实际承载 string(formEncoded),故做类型断言。
func isRefreshGrantRequest(body interface{}) bool {
	s, ok := body.(string)
	if !ok {
		return false
	}
	return strings.Contains(s, "grant_type=refresh_token")
}

// TestIsInvalidGrantError 覆盖回退决策关键函数 isInvalidGrantError。
// 该函数用 errors.As 穿透错误链查找 OAuthCode == "invalid_grant" 的 *OAuth2Error。
// 复盖以下场景:
//   - nil / 普通错误 → false
//   - OAuth2Error(invalid_grant) → true
//   - OAuth2Error(其他 code / 空 code) → false
//   - ServerError 包装 OAuth2Error(invalid_grant)(5xx body 含 oauth error) → true
//   - ServerError 包装 HttpError(无 oauth body) → false
//   - HttpError(无 cause) → false
func TestIsInvalidGrantError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"plain error", errors.New("network reset"), false},
		{
			"OAuth2Error invalid_grant",
			sdkerrors.NewOAuth2Error(400, "invalid_grant", "bad refresh token", "", nil),
			true,
		},
		{
			"OAuth2Error invalid_client",
			sdkerrors.NewOAuth2Error(400, "invalid_client", "bad client", "", nil),
			false,
		},
		{
			"OAuth2Error empty code",
			sdkerrors.NewOAuth2Error(500, "", "", "", nil),
			false,
		},
		{
			"ServerError wrapping OAuth2Error invalid_grant (5xx with oauth body)",
			sdkerrors.NewServerError(
				"invalid_grant", "OAuth2 server error: [OAuth2 invalid_grant]", 500,
				sdkerrors.NewOAuth2Error(400, "invalid_grant", "bad refresh token", "", nil),
			),
			true,
		},
		{
			"ServerError wrapping HttpError (no oauth body)",
			sdkerrors.NewServerError(
				"ServerError", "HTTP request failed", 500,
				sdkerrors.NewHttpError("ClientError", "fail", 500, nil),
			),
			false,
		},
		{
			"HttpError no cause",
			sdkerrors.NewHttpError("ClientError", "fail", 400, nil),
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isInvalidGrantError(tt.err); got != tt.want {
				t.Errorf("isInvalidGrantError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

// TestHuman_Refresh_InvalidGrant_FallsBackToDeviceFlow (回退路径):
// refresh_token 刷新返回 400 invalid_grant → 应回退 device flow 取新 token,
// 而非把错误抛给调用方。断言:返回新 token、device 端点被命中、lastToken 已更新。
func TestHuman_Refresh_InvalidGrant_FallsBackToDeviceFlow(t *testing.T) {
	deviceCalled := false
	mock := &mockAuthHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			switch req.URL {
			case "https://token.example.com":
				if isRefreshGrantRequest(req.Body) {
					// refresh_token 已失效
					return &domain.HttpResponse{
						StatusCode: 400,
						Body:       []byte(`{"error":"invalid_grant","error_description":"refresh token revoked"}`),
					}, nil
				}
				// device flow 轮询 → 返回新 token
				return &domain.HttpResponse{
					StatusCode: 200,
					Body:       makeBoundaryTokenJSON("fb-tok", "fb-rt", 3600),
				}, nil
			case "https://device.example.com":
				deviceCalled = true
				return &domain.HttpResponse{
					StatusCode: 200,
					Body:       makeBoundaryDeviceCodeJSON("dev-fb", 5, 1),
				}, nil
			default:
				return nil, errors.New("unexpected url: " + req.URL)
			}
		},
	}
	p := newBoundaryHumanProvider(t, mock)
	// 已有 token,refresh_token 失效 → refresh 返回 invalid_grant → 回退 device flow。
	p.lastToken = &credential.IDaaSTokenResponse{
		AccessToken:  "old",
		RefreshToken: "old-rt",
		ExpiresIn:    3600,
		TokenType:    "Bearer",
	}

	cred, err := p.GetCredentialWithContext(context.Background())
	if err != nil {
		t.Fatalf("expected fallback to device flow to succeed, got: %v", err)
	}
	if cred == nil {
		t.Fatal("expected non-nil credential from device flow fallback")
	}
	if cred.GetAccessToken() != "fb-tok" {
		t.Errorf("expected 'fb-tok' from device flow fallback, got '%s'", cred.GetAccessToken())
	}
	if !deviceCalled {
		t.Error("expected device authorization endpoint to be hit during invalid_grant fallback")
	}
	// 回退成功后 lastToken 应更新为新 token,后续走正常 refresh 路径。
	if p.lastToken == nil || p.lastToken.AccessToken != "fb-tok" {
		t.Errorf("expected lastToken updated to 'fb-tok', got %+v", p.lastToken)
	}
}

// TestHuman_Refresh_TransientError_NoFallback (不回退路径):
// refresh_token 刷新遇到瞬时错误(网络层) → 不回退 device flow,直接把错误返回调用方,
// 避免每次瞬时故障都强迫用户重新扫码。断言:返回错误、device 端点未被命中。
func TestHuman_Refresh_TransientError_NoFallback(t *testing.T) {
	deviceCalled := false
	mock := &mockAuthHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			if req.URL == "https://device.example.com" {
				deviceCalled = true
				return &domain.HttpResponse{
					StatusCode: 200,
					Body:       makeBoundaryDeviceCodeJSON("dev-x", 5, 1),
				}, nil
			}
			// token endpoint 的 refresh 请求 → 瞬时网络错误(非 invalid_grant)
			return nil, errors.New("connection reset by peer")
		},
	}
	p := newBoundaryHumanProvider(t, mock)
	p.lastToken = &credential.IDaaSTokenResponse{
		AccessToken:  "old",
		RefreshToken: "old-rt",
		ExpiresIn:    3600,
		TokenType:    "Bearer",
	}

	cred, err := p.GetCredentialWithContext(context.Background())
	if err == nil {
		t.Fatal("expected transient refresh error to be propagated, got nil error")
	}
	if cred != nil {
		t.Errorf("expected nil credential on transient error (no fallback), got %v", cred)
	}
	if deviceCalled {
		t.Error("device flow must NOT be triggered on transient refresh error")
	}
}

// TestHuman_Refresh_NonInvalidGrantOAuthError_NoFallback :
// refresh 返回 OAuth2 error 但 code 非 invalid_grant(如 invalid_client) → 不回退。
// invalid_client 表示客户端凭证本身错误,回退 device flow 也救不回来,应直接报错。
func TestHuman_Refresh_NonInvalidGrantOAuthError_NoFallback(t *testing.T) {
	deviceCalled := false
	mock := &mockAuthHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			if req.URL == "https://device.example.com" {
				deviceCalled = true
				return &domain.HttpResponse{
					StatusCode: 200,
					Body:       makeBoundaryDeviceCodeJSON("dev-y", 5, 1),
				}, nil
			}
			return &domain.HttpResponse{
				StatusCode: 401,
				Body:       []byte(`{"error":"invalid_client","error_description":"client authentication failed"}`),
			}, nil
		},
	}
	p := newBoundaryHumanProvider(t, mock)
	p.lastToken = &credential.IDaaSTokenResponse{
		AccessToken:  "old",
		RefreshToken: "old-rt",
		ExpiresIn:    3600,
		TokenType:    "Bearer",
	}

	cred, err := p.GetCredentialWithContext(context.Background())
	if err == nil {
		t.Fatal("expected invalid_client error to be propagated, got nil error")
	}
	if cred != nil {
		t.Errorf("expected nil credential on invalid_client (no fallback), got %v", cred)
	}
	if deviceCalled {
		t.Error("device flow must NOT be triggered on non-invalid_grant OAuth2 error")
	}
}
