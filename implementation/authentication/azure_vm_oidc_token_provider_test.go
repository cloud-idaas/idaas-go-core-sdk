package authentication

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aliyun/idaas-go-core-sdk/constants"
	"github.com/aliyun/idaas-go-core-sdk/domain"
	"github.com/aliyun/idaas-go-core-sdk/enums"
)

// mockAzureHttpClient 用于捕获请求参数并返回预设响应，实现 http.HttpClient 接口
type mockAzureHttpClient struct {
	executeFn   func(req *domain.HttpRequest) (*domain.HttpResponse, error)
	callCount   int
	lastRequest *domain.HttpRequest
}

func (m *mockAzureHttpClient) Execute(req *domain.HttpRequest) (*domain.HttpResponse, error) {
	m.callCount++
	m.lastRequest = req
	return m.executeFn(req)
}

func (m *mockAzureHttpClient) Get(url string, headers map[string]string) (*domain.HttpResponse, error) {
	return m.Execute(&domain.HttpRequest{Method: enums.HttpMethodGet, URL: url, Headers: headers})
}

func (m *mockAzureHttpClient) Post(url string, headers map[string]string, body interface{}) (*domain.HttpResponse, error) {
	return m.Execute(&domain.HttpRequest{Method: enums.HttpMethodPost, URL: url, Headers: headers, Body: body})
}

// makeAzureImdsResponseBody 构造一个合法的 Azure IMDS JSON 响应体
func makeAzureImdsResponseBody(accessToken string, expiresOn int64) []byte {
	body := map[string]string{
		"access_token":   accessToken,
		"client_id":      "fake-client-id",
		"expires_in":     "3599",
		"expires_on":     strconv.FormatInt(expiresOn, 10),
		"ext_expires_in": "3599",
		"not_before":     strconv.FormatInt(expiresOn-3600, 10),
		"resource":       "https://idaas.example.com",
		"token_type":     "Bearer",
	}
	b, _ := json.Marshal(body)
	return b
}

// makeFakeJwtForAzure 构造一个包含指定 exp 的伪 JWT（与 GCP 测试中保持一致的工具）
func makeFakeJwtForAzure(exp int64) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payloadJson, _ := json.Marshal(map[string]interface{}{"exp": exp, "aud": "https://idaas.example.com"})
	payload := base64.RawURLEncoding.EncodeToString(payloadJson)
	return header + "." + payload + ".signature"
}

func TestAzureVmOidcTokenProvider_GetOidcToken_Success(t *testing.T) {
	resource := "https://idaas.example.com"
	expectedToken := makeFakeJwtForAzure(time.Now().Add(time.Hour).Unix())
	expiresOn := time.Now().Add(time.Hour).Unix()

	mock := &mockAzureHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 200, Body: makeAzureImdsResponseBody(expectedToken, expiresOn)}, nil
		},
	}

	provider := NewAzureVmOidcTokenProvider(mock, resource)
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
	if got := mock.lastRequest.Headers[constants.HeaderMetadata]; got != constants.HeaderMetadataValueTrue {
		t.Errorf("expected header %s=%s, got %s", constants.HeaderMetadata, constants.HeaderMetadataValueTrue, got)
	}

	// 校验 URL 包含 URL-encoded resource、api-version 与 IMDS 主机
	wantSubstr := "resource=" + url.QueryEscape(resource)
	if !strings.Contains(mock.lastRequest.URL, wantSubstr) {
		t.Errorf("URL missing encoded resource %q, got URL=%s", wantSubstr, mock.lastRequest.URL)
	}
	if !strings.Contains(mock.lastRequest.URL, "api-version=2018-02-01") {
		t.Errorf("URL missing api-version=2018-02-01, got URL=%s", mock.lastRequest.URL)
	}
	if !strings.HasPrefix(mock.lastRequest.URL, "http://169.254.169.254/") {
		t.Errorf("URL should target IMDS 169.254.169.254, got %s", mock.lastRequest.URL)
	}
}

func TestAzureVmOidcTokenProvider_CacheHitWhenNotExpiring(t *testing.T) {
	expectedToken := makeFakeJwtForAzure(time.Now().Add(time.Hour).Unix())
	expiresOn := time.Now().Add(time.Hour).Unix()
	mock := &mockAzureHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 200, Body: makeAzureImdsResponseBody(expectedToken, expiresOn)}, nil
		},
	}

	provider := NewAzureVmOidcTokenProvider(mock, "https://idaas.example.com")
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

func TestAzureVmOidcTokenProvider_RefreshWhenSoonExpiring(t *testing.T) {
	// 9 分钟后过期 -> 小于 10 分钟阈值 -> 必须刷新
	soonExpireToken := makeFakeJwtForAzure(time.Now().Add(9 * time.Minute).Unix())
	farExpireToken := makeFakeJwtForAzure(time.Now().Add(time.Hour).Unix())
	soonExpireOn := time.Now().Add(9 * time.Minute).Unix()
	farExpireOn := time.Now().Add(time.Hour).Unix()

	responses := [][]byte{
		makeAzureImdsResponseBody(soonExpireToken, soonExpireOn),
		makeAzureImdsResponseBody(farExpireToken, farExpireOn),
	}
	idx := 0
	mock := &mockAzureHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			body := responses[idx]
			idx++
			return &domain.HttpResponse{StatusCode: 200, Body: body}, nil
		},
	}

	provider := NewAzureVmOidcTokenProvider(mock, "https://idaas.example.com")
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

func TestAzureVmOidcTokenProvider_FallbackToJwtExpWhenExpiresOnInvalid(t *testing.T) {
	// expires_on 缺失或不可解析时，应回退到 JWT payload 的 exp
	token := makeFakeJwtForAzure(time.Now().Add(time.Hour).Unix())
	body := []byte(fmt.Sprintf(`{"access_token":%q,"expires_on":"not-a-number","token_type":"Bearer"}`, token))

	mock := &mockAzureHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 200, Body: body}, nil
		},
	}

	provider := NewAzureVmOidcTokenProvider(mock, "https://idaas.example.com")
	if _, err := provider.GetOidcToken(); err != nil {
		t.Fatalf("first call failed: %v", err)
	}
	if _, err := provider.GetOidcToken(); err != nil {
		t.Fatalf("second call failed: %v", err)
	}

	// 用 JWT exp 作为兜底，距离过期还有 1 小时 -> 命中缓存
	if mock.callCount != 1 {
		t.Errorf("expected cache hit via JWT exp fallback, got %d HTTP calls", mock.callCount)
	}
}

func TestAzureVmOidcTokenProvider_NoExpInfoDisablesCache(t *testing.T) {
	// expires_on 无效 + access_token 不是合法 JWT -> 每次都重新拉取
	body := []byte(`{"access_token":"opaque-not-jwt","expires_on":"bad","token_type":"Bearer"}`)
	mock := &mockAzureHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 200, Body: body}, nil
		},
	}

	provider := NewAzureVmOidcTokenProvider(mock, "https://idaas.example.com")
	for i := 0; i < 3; i++ {
		if _, err := provider.GetOidcToken(); err != nil {
			t.Fatalf("call #%d failed: %v", i+1, err)
		}
	}
	if mock.callCount != 3 {
		t.Errorf("expected 3 HTTP calls (no exp info, no cache), got %d", mock.callCount)
	}
}

func TestAzureVmOidcTokenProvider_HttpError(t *testing.T) {
	mock := &mockAzureHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 400, Body: []byte(`{"error":"invalid_request"}`)}, nil
		},
	}

	provider := NewAzureVmOidcTokenProvider(mock, "https://idaas.example.com")
	_, err := provider.GetOidcToken()
	if err == nil {
		t.Fatal("expected error for HTTP 400, got nil")
	}
	if !strings.Contains(err.Error(), "400") {
		t.Errorf("error should mention status code 400, got: %v", err)
	}
}

func TestAzureVmOidcTokenProvider_InvalidJson(t *testing.T) {
	mock := &mockAzureHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 200, Body: []byte(`not-a-json-body`)}, nil
		},
	}

	provider := NewAzureVmOidcTokenProvider(mock, "https://idaas.example.com")
	_, err := provider.GetOidcToken()
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestAzureVmOidcTokenProvider_EmptyAccessToken(t *testing.T) {
	mock := &mockAzureHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 200, Body: []byte(`{"access_token":"","token_type":"Bearer"}`)}, nil
		},
	}

	provider := NewAzureVmOidcTokenProvider(mock, "https://idaas.example.com")
	_, err := provider.GetOidcToken()
	if err == nil {
		t.Fatal("expected error for empty access_token, got nil")
	}
}

func TestAzureVmOidcTokenProvider_MissingResource(t *testing.T) {
	mock := &mockAzureHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 200, Body: []byte(`{"access_token":"x"}`)}, nil
		},
	}
	provider := NewAzureVmOidcTokenProvider(mock, "")
	_, err := provider.GetOidcToken()
	if err == nil {
		t.Fatal("expected error when resource is empty, got nil")
	}
	if mock.callCount != 0 {
		t.Errorf("HTTP client should not be called when resource missing, got %d calls", mock.callCount)
	}
}

func TestAzureVmIdentityTokenUrlTemplate_FormatsCorrectly(t *testing.T) {
	got := fmt.Sprintf(constants.AzureVmIdentityTokenUrlTemplate, url.QueryEscape("https://idaas.example.com"))
	want := "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fidaas.example.com"
	if got != want {
		t.Errorf("URL template mismatch:\n  want: %s\n  got:  %s", want, got)
	}
}

func TestResolveAzureTokenExpiresAt_BoundaryConditions(t *testing.T) {
	tests := []struct {
		name         string
		expiresOnStr string
		jwtToken     string
		wantExp      int64
		wantZero     bool // true 表示期望返回 0（禁用缓存）
	}{
		{
			name:         "valid expires_on takes precedence",
			expiresOnStr: "1700000000",
			jwtToken:     makeFakeJwtForAzure(1600000000),
			wantExp:      1700000000,
		},
		{
			name:         "expires_on non-numeric falls back to JWT exp",
			expiresOnStr: "not-a-number",
			jwtToken:     makeFakeJwtForAzure(1700000000),
			wantExp:      1700000000,
		},
		{
			name:         "expires_on negative falls back to JWT exp",
			expiresOnStr: "-100",
			jwtToken:     makeFakeJwtForAzure(1700000000),
			wantExp:      1700000000,
		},
		{
			name:         "expires_on empty falls back to JWT exp",
			expiresOnStr: "",
			jwtToken:     makeFakeJwtForAzure(1700000000),
			wantExp:      1700000000,
		},
		{
			name:         "both invalid returns zero",
			expiresOnStr: "invalid",
			jwtToken:     "not-a-jwt",
			wantZero:     true,
		},
		{
			name:         "empty expires_on and invalid JWT returns zero",
			expiresOnStr: "",
			jwtToken:     "",
			wantZero:     true,
		},
		{
			name:         "expires_on zero falls back to JWT exp",
			expiresOnStr: "0",
			jwtToken:     makeFakeJwtForAzure(1700000000),
			wantExp:      1700000000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveAzureTokenExpiresAt(tt.expiresOnStr, tt.jwtToken)
			if tt.wantZero {
				if got != 0 {
					t.Errorf("expected 0 (cache disabled), got %d", got)
				}
			} else {
				if got != tt.wantExp {
					t.Errorf("expected %d, got %d", tt.wantExp, got)
				}
			}
		})
	}
}
