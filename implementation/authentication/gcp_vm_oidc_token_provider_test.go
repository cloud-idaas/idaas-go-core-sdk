package authentication

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/cloud-idaas/idaas-go-core-sdk/constants"
	"github.com/cloud-idaas/idaas-go-core-sdk/domain"
	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
)

// mockGcpHttpClient 用于捕获请求参数并返回预设响应，实现 http.HttpClient 接口
type mockGcpHttpClient struct {
	executeFn   func(req *domain.HttpRequest) (*domain.HttpResponse, error)
	callCount   int
	lastRequest *domain.HttpRequest
}

func (m *mockGcpHttpClient) Execute(req *domain.HttpRequest) (*domain.HttpResponse, error) {
	m.callCount++
	m.lastRequest = req
	return m.executeFn(req)
}

func (m *mockGcpHttpClient) Get(url string, headers map[string]string) (*domain.HttpResponse, error) {
	return m.Execute(&domain.HttpRequest{Method: enums.HttpMethodGet, URL: url, Headers: headers})
}

func (m *mockGcpHttpClient) Post(url string, headers map[string]string, body interface{}) (*domain.HttpResponse, error) {
	return m.Execute(&domain.HttpRequest{Method: enums.HttpMethodPost, URL: url, Headers: headers, Body: body})
}

// makeFakeJwt 构造一个 payload 包含指定 exp 的伪 JWT（不做签名，仅用于解析测试）
func makeFakeJwt(exp int64) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payloadJson, _ := json.Marshal(map[string]interface{}{"exp": exp, "aud": "https://example.com"})
	payload := base64.RawURLEncoding.EncodeToString(payloadJson)
	return header + "." + payload + ".signature"
}

func TestGcpVmOidcTokenProvider_GetOidcToken_Success(t *testing.T) {
	audience := "https://idaas.example.com/issuer"
	expectedToken := makeFakeJwt(time.Now().Add(time.Hour).Unix())

	mock := &mockGcpHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 200, Body: []byte(expectedToken)}, nil
		},
	}

	provider := NewGcpVmOidcTokenProvider(mock, audience)
	token, err := provider.GetOidcToken()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != expectedToken {
		t.Errorf("token mismatch: want %s, got %s", expectedToken, token)
	}

	// 校验请求方法 / Header
	if mock.lastRequest.Method != enums.HttpMethodGet {
		t.Errorf("expected GET, got %v", mock.lastRequest.Method)
	}
	if got := mock.lastRequest.Headers[constants.HeaderMetadataFlavor]; got != constants.HeaderMetadataFlavorValueGoogle {
		t.Errorf("expected header %s=%s, got %s", constants.HeaderMetadataFlavor, constants.HeaderMetadataFlavorValueGoogle, got)
	}

	// 校验 URL 包含 URL-encoded audience 与 format=full
	wantSubstr := "audience=" + url.QueryEscape(audience)
	if !strings.Contains(mock.lastRequest.URL, wantSubstr) {
		t.Errorf("URL missing encoded audience %q, got URL=%s", wantSubstr, mock.lastRequest.URL)
	}
	if !strings.Contains(mock.lastRequest.URL, "format=full") {
		t.Errorf("URL missing format=full, got URL=%s", mock.lastRequest.URL)
	}
	if !strings.HasPrefix(mock.lastRequest.URL, "http://metadata.google.internal/") {
		t.Errorf("URL should target metadata.google.internal, got %s", mock.lastRequest.URL)
	}
}

func TestGcpVmOidcTokenProvider_CacheHitWhenNotExpiring(t *testing.T) {
	expectedToken := makeFakeJwt(time.Now().Add(time.Hour).Unix())
	mock := &mockGcpHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 200, Body: []byte(expectedToken)}, nil
		},
	}

	provider := NewGcpVmOidcTokenProvider(mock, "https://issuer.example.com")
	if _, err := provider.GetOidcToken(); err != nil {
		t.Fatalf("first call failed: %v", err)
	}
	if _, err := provider.GetOidcToken(); err != nil {
		t.Fatalf("second call failed: %v", err)
	}

	if mock.callCount != 1 {
		t.Errorf("expected 1 HTTP call due to cache hit, got %d", mock.callCount)
	}
}

func TestGcpVmOidcTokenProvider_RefreshWhenSoonExpiring(t *testing.T) {
	// 9 分钟后过期 -> 小于 10 分钟阈值 -> 必须刷新
	soonExpireToken := makeFakeJwt(time.Now().Add(9 * time.Minute).Unix())
	farExpireToken := makeFakeJwt(time.Now().Add(time.Hour).Unix())

	responses := []string{soonExpireToken, farExpireToken}
	idx := 0
	mock := &mockGcpHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			body := responses[idx]
			idx++
			return &domain.HttpResponse{StatusCode: 200, Body: []byte(body)}, nil
		},
	}

	provider := NewGcpVmOidcTokenProvider(mock, "https://issuer.example.com")
	first, err := provider.GetOidcToken()
	if err != nil {
		t.Fatalf("first call failed: %v", err)
	}
	second, err := provider.GetOidcToken()
	if err != nil {
		t.Fatalf("second call failed: %v", err)
	}

	if first != soonExpireToken {
		t.Errorf("first token mismatch")
	}
	if second != farExpireToken {
		t.Errorf("expected refresh on second call to return new token")
	}
	if mock.callCount != 2 {
		t.Errorf("expected 2 HTTP calls (refresh due to soon expiration), got %d", mock.callCount)
	}
}

func TestGcpVmOidcTokenProvider_NonJwtBodyDisablesExpCache(t *testing.T) {
	// 非标准 JWT -> exp 解析失败 -> 每次都重新拉取
	const opaqueToken = "not-a-jwt-token"
	mock := &mockGcpHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 200, Body: []byte(opaqueToken)}, nil
		},
	}

	provider := NewGcpVmOidcTokenProvider(mock, "https://issuer.example.com")
	for i := 0; i < 3; i++ {
		token, err := provider.GetOidcToken()
		if err != nil {
			t.Fatalf("call #%d failed: %v", i+1, err)
		}
		if token != opaqueToken {
			t.Errorf("call #%d token mismatch", i+1)
		}
	}
	if mock.callCount != 3 {
		t.Errorf("expected 3 HTTP calls (no exp cache), got %d", mock.callCount)
	}
}

func TestGcpVmOidcTokenProvider_HttpError(t *testing.T) {
	mock := &mockGcpHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 403, Body: []byte("Forbidden")}, nil
		},
	}

	provider := NewGcpVmOidcTokenProvider(mock, "https://issuer.example.com")
	_, err := provider.GetOidcToken()
	if err == nil {
		t.Fatal("expected error for HTTP 403, got nil")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("error should mention status code 403, got: %v", err)
	}
}

func TestGcpVmOidcTokenProvider_EmptyBody(t *testing.T) {
	mock := &mockGcpHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 200, Body: []byte("   ")}, nil
		},
	}

	provider := NewGcpVmOidcTokenProvider(mock, "https://issuer.example.com")
	_, err := provider.GetOidcToken()
	if err == nil {
		t.Fatal("expected error for empty body, got nil")
	}
}

func TestGcpVmOidcTokenProvider_MissingAudience(t *testing.T) {
	mock := &mockGcpHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 200, Body: []byte("anything")}, nil
		},
	}
	provider := NewGcpVmOidcTokenProvider(mock, "")
	_, err := provider.GetOidcToken()
	if err == nil {
		t.Fatal("expected error when audience is empty, got nil")
	}
	if mock.callCount != 0 {
		t.Errorf("HTTP client should not be called when audience missing, got %d calls", mock.callCount)
	}
}

func TestGcpVmIdentityTokenUrlTemplate_FormatsCorrectly(t *testing.T) {
	// 防回归：确认常量模板的两个占位符（audience、format=full）位置正确
	got := fmt.Sprintf(constants.GcpVmIdentityTokenUrlTemplate, url.QueryEscape("https://a.example.com/issuer"))
	want := "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=https%3A%2F%2Fa.example.com%2Fissuer&format=full"
	if got != want {
		t.Errorf("URL template mismatch:\n  want: %s\n  got:  %s", want, got)
	}
}
