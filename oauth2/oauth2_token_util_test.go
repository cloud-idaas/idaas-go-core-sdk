package oauth2

import (
	"encoding/json"
	stderrors "errors"
	"net/http"
	"testing"
	"time"

	"github.com/aliyun/idaas-go-core-sdk/credential"
	"github.com/aliyun/idaas-go-core-sdk/domain"
	sdkerrors "github.com/aliyun/idaas-go-core-sdk/errors"
)

// MockHttpClient 模拟 HTTP 客户端
type MockHttpClient struct {
	Response *domain.HttpResponse
	Error    error
}

func (m *MockHttpClient) Execute(request *domain.HttpRequest) (*domain.HttpResponse, error) {
	if m.Error != nil {
		return nil, m.Error
	}
	return m.Response, nil
}

func (m *MockHttpClient) Get(url string, headers map[string]string) (*domain.HttpResponse, error) {
	if m.Error != nil {
		return nil, m.Error
	}
	return m.Response, nil
}

func (m *MockHttpClient) Post(url string, headers map[string]string, body interface{}) (*domain.HttpResponse, error) {
	if m.Error != nil {
		return nil, m.Error
	}
	return m.Response, nil
}

// createSuccessTokenResponse 创建成功的 Token 响应
func createSuccessTokenResponse(t *testing.T) *domain.HttpResponse {
	t.Helper()
	tokenResp := credential.IDaaSTokenResponse{
		AccessToken:  "test_access_token",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		Scope:        "read write",
		RefreshToken: "test_refresh_token",
		IdToken:      "test_id_token",
		ReceivedAt:   time.Now(),
	}
	body, err := json.Marshal(tokenResp)
	if err != nil {
		t.Fatalf("failed to marshal token response: %v", err)
	}
	return &domain.HttpResponse{
		StatusCode: http.StatusOK,
		Headers:    map[string][]string{"Content-Type": {"application/json"}},
		Body:       body,
	}
}

// createSuccessDeviceCodeResponse 创建成功的 Device Code 响应
func createSuccessDeviceCodeResponse(t *testing.T) *domain.HttpResponse {
	t.Helper()
	deviceCodeResp := domain.DeviceCodeResponse{
		DeviceCode:              "test_device_code",
		UserCode:                "USER1234",
		VerificationURI:         "https://example.com/verify",
		VerificationURIComplete: "https://example.com/verify?user_code=USER1234",
		ExpiresIn:               600,
		Interval:                5,
	}
	body, err := json.Marshal(deviceCodeResp)
	if err != nil {
		t.Fatalf("failed to marshal device code response: %v", err)
	}
	return &domain.HttpResponse{
		StatusCode: http.StatusOK,
		Headers:    map[string][]string{"Content-Type": {"application/json"}},
		Body:       body,
	}
}

// createErrorResponse 创建错误响应
func createErrorResponse(statusCode int) *domain.HttpResponse {
	return &domain.HttpResponse{
		StatusCode: statusCode,
		Headers:    map[string][]string{},
		Body:       []byte(`{"error":"invalid_request","error_description":"Invalid request"}`),
	}
}

// createOAuth2ErrorResponse 创建带具体 OAuth2 error code 的错误响应
func createOAuth2ErrorResponse(statusCode int, oauthCode, desc string) *domain.HttpResponse {
	body := `{"error":"` + oauthCode + `","error_description":"` + desc + `"}`
	return &domain.HttpResponse{
		StatusCode: statusCode,
		Headers:    map[string][]string{},
		Body:       []byte(body),
	}
}

// createNonOAuth2ErrorResponse 创建非 OAuth2 标准的错误响应（HTML / 纯文本）
func createNonOAuth2ErrorResponse(statusCode int) *domain.HttpResponse {
	return &domain.HttpResponse{
		StatusCode: statusCode,
		Headers:    map[string][]string{},
		Body:       []byte(`<html><body>500 Internal Server Error</body></html>`),
	}
}

// TestParseOAuth2Error_StandardError 验证标准 OAuth2 error 响应被正确解析为 *OAuth2Error
func TestParseOAuth2Error_StandardError(t *testing.T) {
	mockClient := &MockHttpClient{
		Response: createOAuth2ErrorResponse(http.StatusBadRequest, "authorization_pending", "user has not approved yet"),
	}
	util := NewOAuth2TokenUtil(mockClient)

	_, err := util.GetTokenByDeviceCode("https://example.com/oauth/token", "cid", "device-code-123")
	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	var oauthErr *sdkerrors.OAuth2Error
	if !stderrors.As(err, &oauthErr) {
		t.Fatalf("Expected *OAuth2Error, got: %T", err)
	}
	if oauthErr.OAuthCode != "authorization_pending" {
		t.Errorf("Expected OAuthCode=authorization_pending, got %q", oauthErr.OAuthCode)
	}
	if oauthErr.OAuthDescription != "user has not approved yet" {
		t.Errorf("Expected OAuthDescription, got %q", oauthErr.OAuthDescription)
	}
	if oauthErr.HTTPStatus != http.StatusBadRequest {
		t.Errorf("Expected HTTPStatus=400, got %d", oauthErr.HTTPStatus)
	}
}

// TestParseOAuth2Error_NonStandardFallback 验证非 OAuth2 标准响应降级为 *HttpError
func TestParseOAuth2Error_NonStandardFallback(t *testing.T) {
	mockClient := &MockHttpClient{
		Response: createNonOAuth2ErrorResponse(http.StatusInternalServerError),
	}
	util := NewOAuth2TokenUtil(mockClient)

	_, err := util.GetTokenByClientCredentials("https://example.com/oauth/token", "cid", "secret", "")
	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	// 非标响应不能匹配 OAuth2Error
	var oauthErr *sdkerrors.OAuth2Error
	if stderrors.As(err, &oauthErr) {
		t.Errorf("Non-OAuth2 response 不应该被解析为 OAuth2Error，但被解析了: %+v", oauthErr)
	}

	var httpErr *sdkerrors.HttpError
	if !stderrors.As(err, &httpErr) {
		t.Fatalf("Expected fallback to *HttpError, got: %T", err)
	}
	if httpErr.StatusCode != http.StatusInternalServerError {
		t.Errorf("Expected StatusCode=500, got %d", httpErr.StatusCode)
	}
}

// TestGetTokenByClientCredentialsBasic_AuthHeader 验证 Basic Auth 头被正确发送
func TestGetTokenByClientCredentialsBasic_AuthHeader(t *testing.T) {
	var capturedHeaders map[string]string
	mockClient := &headerCapturingClient{
		response: createSuccessTokenResponse(t),
		onCall: func(req *domain.HttpRequest) {
			capturedHeaders = req.Headers
		},
	}
	util := NewOAuth2TokenUtil(mockClient)

	_, err := util.GetTokenByClientCredentialsBasic(
		"https://example.com/oauth/token",
		"client-id-x",
		"super-secret",
		"read",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	auth := capturedHeaders["Authorization"]
	// "client-id-x:super-secret" 的 base64 = Y2xpZW50LWlkLXg6c3VwZXItc2VjcmV0
	const expected = "Basic Y2xpZW50LWlkLXg6c3VwZXItc2VjcmV0"
	if auth != expected {
		t.Errorf("Authorization header 错误: 期望 %q, 实际 %q", expected, auth)
	}
}

// headerCapturingClient 用于捕获请求 header
type headerCapturingClient struct {
	response *domain.HttpResponse
	onCall   func(*domain.HttpRequest)
}

func (c *headerCapturingClient) Execute(req *domain.HttpRequest) (*domain.HttpResponse, error) {
	if c.onCall != nil {
		c.onCall(req)
	}
	return c.response, nil
}
func (c *headerCapturingClient) Get(string, map[string]string) (*domain.HttpResponse, error) {
	return c.response, nil
}
func (c *headerCapturingClient) Post(string, map[string]string, interface{}) (*domain.HttpResponse, error) {
	return c.response, nil
}

// TestGetTokenByClientCredentials_Success 测试通过 client_credentials 成功获取令牌
func TestGetTokenByClientCredentials_Success(t *testing.T) {
	mockClient := &MockHttpClient{
		Response: createSuccessTokenResponse(t),
	}
	util := NewOAuth2TokenUtil(mockClient)

	resp, err := util.GetTokenByClientCredentials(
		"https://example.com/oauth/token",
		"test_client_id",
		"test_client_secret",
		"read write",
	)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if resp == nil {
		t.Fatal("Expected response, got nil")
	}
	if resp.AccessToken != "test_access_token" {
		t.Errorf("Expected access token 'test_access_token', got '%s'", resp.AccessToken)
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("Expected token type 'Bearer', got '%s'", resp.TokenType)
	}
	if resp.ExpiresIn != 3600 {
		t.Errorf("Expected expires_in 3600, got %d", resp.ExpiresIn)
	}
	if resp.Scope != "read write" {
		t.Errorf("Expected scope 'read write', got '%s'", resp.Scope)
	}
	if resp.RefreshToken != "test_refresh_token" {
		t.Errorf("Expected refresh token 'test_refresh_token', got '%s'", resp.RefreshToken)
	}
	if resp.IdToken != "test_id_token" {
		t.Errorf("Expected id_token 'test_id_token', got '%s'", resp.IdToken)
	}
}

// TestGetTokenByClientCredentials_WithoutScope 测试不带 scope 参数
func TestGetTokenByClientCredentials_WithoutScope(t *testing.T) {
	mockClient := &MockHttpClient{
		Response: createSuccessTokenResponse(t),
	}
	util := NewOAuth2TokenUtil(mockClient)

	resp, err := util.GetTokenByClientCredentials(
		"https://example.com/oauth/token",
		"test_client_id",
		"test_client_secret",
		"",
	)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if resp == nil {
		t.Fatal("Expected response, got nil")
	}
}

// TestGetTokenByClientCredentials_HttpError 测试 HTTP 错误
//
// createErrorResponse 返回的 body 形如 {"error":"client_error","error_description":"..."}，
// 新实现会优先按 OAuth2 标准错误解析为 *OAuth2Error；只有非标响应才降级为 HttpError。
func TestGetTokenByClientCredentials_HttpError(t *testing.T) {
	mockClient := &MockHttpClient{
		Response: createErrorResponse(http.StatusBadRequest),
	}
	util := NewOAuth2TokenUtil(mockClient)

	_, err := util.GetTokenByClientCredentials(
		"https://example.com/oauth/token",
		"test_client_id",
		"test_client_secret",
		"read",
	)

	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	var oauth2Err *sdkerrors.OAuth2Error
	if !stderrors.As(err, &oauth2Err) {
		t.Errorf("Expected OAuth2Error, got: %T", err)
	}
	if oauth2Err.HTTPStatus != http.StatusBadRequest {
		t.Errorf("Expected HTTPStatus 400, got %d", oauth2Err.HTTPStatus)
	}
}

// TestGetTokenByClientCredentials_NetworkError 测试网络错误
func TestGetTokenByClientCredentials_NetworkError(t *testing.T) {
	mockClient := &MockHttpClient{
		Error: stderrors.New("network error"),
	}
	util := NewOAuth2TokenUtil(mockClient)

	_, err := util.GetTokenByClientCredentials(
		"https://example.com/oauth/token",
		"test_client_id",
		"test_client_secret",
		"read",
	)

	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	if err.Error() != "network error" {
		t.Errorf("Expected 'network error', got: %v", err)
	}
}

// TestGetTokenByClientCredentials_InvalidJson 测试无效的 JSON 响应
func TestGetTokenByClientCredentials_InvalidJson(t *testing.T) {
	mockClient := &MockHttpClient{
		Response: &domain.HttpResponse{
			StatusCode: http.StatusOK,
			Headers:    map[string][]string{},
			Body:       []byte("invalid json"),
		},
	}
	util := NewOAuth2TokenUtil(mockClient)

	_, err := util.GetTokenByClientCredentials(
		"https://example.com/oauth/token",
		"test_client_id",
		"test_client_secret",
		"read",
	)

	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	var encodingErr *sdkerrors.EncodingError
	if !stderrors.As(err, &encodingErr) {
		t.Errorf("Expected EncodingError, got: %T", err)
	}
}

// TestGetTokenByJwtBearer_Success 测试通过 jwt-bearer 成功获取令牌
func TestGetTokenByJwtBearer_Success(t *testing.T) {
	mockClient := &MockHttpClient{
		Response: createSuccessTokenResponse(t),
	}
	util := NewOAuth2TokenUtil(mockClient)

	resp, err := util.GetTokenByJwtBearer(
		"https://example.com/oauth/token",
		"test_client_id",
		"test_jwt_assertion",
		"read write",
	)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if resp == nil {
		t.Fatal("Expected response, got nil")
	}
	if resp.AccessToken != "test_access_token" {
		t.Errorf("Expected access token 'test_access_token', got '%s'", resp.AccessToken)
	}
}

// TestGetTokenByJwtBearer_WithoutScope 测试不带 scope 参数
func TestGetTokenByJwtBearer_WithoutScope(t *testing.T) {
	mockClient := &MockHttpClient{
		Response: createSuccessTokenResponse(t),
	}
	util := NewOAuth2TokenUtil(mockClient)

	resp, err := util.GetTokenByJwtBearer(
		"https://example.com/oauth/token",
		"test_client_id",
		"test_jwt_assertion",
		"",
	)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if resp == nil {
		t.Fatal("Expected response, got nil")
	}
}

// TestGetTokenByJwtBearer_HttpError 测试 HTTP 错误
func TestGetTokenByJwtBearer_HttpError(t *testing.T) {
	mockClient := &MockHttpClient{
		Response: createErrorResponse(http.StatusUnauthorized),
	}
	util := NewOAuth2TokenUtil(mockClient)

	_, err := util.GetTokenByJwtBearer(
		"https://example.com/oauth/token",
		"test_client_id",
		"test_jwt_assertion",
		"read",
	)

	if err == nil {
		t.Fatal("Expected error, got nil")
	}
}

// TestGetTokenByRefreshToken_Success 测试通过 refresh_token 成功获取令牌
func TestGetTokenByRefreshToken_Success(t *testing.T) {
	mockClient := &MockHttpClient{
		Response: createSuccessTokenResponse(t),
	}
	util := NewOAuth2TokenUtil(mockClient)

	resp, err := util.GetTokenByRefreshToken(
		"https://example.com/oauth/token",
		"test_client_id",
		"test_client_secret",
		"test_refresh_token",
		"read write",
	)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if resp == nil {
		t.Fatal("Expected response, got nil")
	}
	if resp.AccessToken != "test_access_token" {
		t.Errorf("Expected access token 'test_access_token', got '%s'", resp.AccessToken)
	}
}

// TestGetTokenByRefreshToken_WithoutScope 测试不带 scope 参数
func TestGetTokenByRefreshToken_WithoutScope(t *testing.T) {
	mockClient := &MockHttpClient{
		Response: createSuccessTokenResponse(t),
	}
	util := NewOAuth2TokenUtil(mockClient)

	resp, err := util.GetTokenByRefreshToken(
		"https://example.com/oauth/token",
		"test_client_id",
		"test_client_secret",
		"test_refresh_token",
		"",
	)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if resp == nil {
		t.Fatal("Expected response, got nil")
	}
}

// TestGetTokenByRefreshToken_HttpError 测试 HTTP 错误
func TestGetTokenByRefreshToken_HttpError(t *testing.T) {
	mockClient := &MockHttpClient{
		Response: createErrorResponse(http.StatusBadRequest),
	}
	util := NewOAuth2TokenUtil(mockClient)

	_, err := util.GetTokenByRefreshToken(
		"https://example.com/oauth/token",
		"test_client_id",
		"test_client_secret",
		"test_refresh_token",
		"read",
	)

	if err == nil {
		t.Fatal("Expected error, got nil")
	}
}

// TestTokenExchange_Success 测试令牌交换成功
func TestTokenExchange_Success(t *testing.T) {
	mockClient := &MockHttpClient{
		Response: createSuccessTokenResponse(t),
	}
	util := NewOAuth2TokenUtil(mockClient)

	resp, err := util.TokenExchange(
		"https://example.com/oauth/token",
		"test_client_id",
		"test_client_secret",
		"subject_token_value",
		"urn:ietf:params:oauth:token-type:access_token",
		"actor_token_value",
		"urn:ietf:params:oauth:token-type:access_token",
		"urn:ietf:params:oauth:token-type:jwt",
		"read write",
	)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if resp == nil {
		t.Fatal("Expected response, got nil")
	}
	if resp.AccessToken != "test_access_token" {
		t.Errorf("Expected access token 'test_access_token', got '%s'", resp.AccessToken)
	}
}

// TestTokenExchange_WithoutOptionalParams 测试不带可选参数
func TestTokenExchange_WithoutOptionalParams(t *testing.T) {
	mockClient := &MockHttpClient{
		Response: createSuccessTokenResponse(t),
	}
	util := NewOAuth2TokenUtil(mockClient)

	resp, err := util.TokenExchange(
		"https://example.com/oauth/token",
		"test_client_id",
		"test_client_secret",
		"subject_token_value",
		"urn:ietf:params:oauth:token-type:access_token",
		"",
		"",
		"",
		"",
	)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if resp == nil {
		t.Fatal("Expected response, got nil")
	}
}

// TestTokenExchange_HttpError 测试 HTTP 错误
func TestTokenExchange_HttpError(t *testing.T) {
	mockClient := &MockHttpClient{
		Response: createErrorResponse(http.StatusBadRequest),
	}
	util := NewOAuth2TokenUtil(mockClient)

	_, err := util.TokenExchange(
		"https://example.com/oauth/token",
		"test_client_id",
		"test_client_secret",
		"subject_token_value",
		"urn:ietf:params:oauth:token-type:access_token",
		"",
		"",
		"",
		"",
	)

	if err == nil {
		t.Fatal("Expected error, got nil")
	}
}

// TestGetDeviceCode_Success 测试成功获取 Device Code
func TestGetDeviceCode_Success(t *testing.T) {
	mockClient := &MockHttpClient{
		Response: createSuccessDeviceCodeResponse(t),
	}
	util := NewOAuth2TokenUtil(mockClient)

	resp, err := util.GetDeviceCode(
		"https://example.com/oauth/device_authorization",
		"test_client_id",
		"read write",
	)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if resp == nil {
		t.Fatal("Expected response, got nil")
	}
	if resp.DeviceCode != "test_device_code" {
		t.Errorf("Expected device code 'test_device_code', got '%s'", resp.DeviceCode)
	}
	if resp.UserCode != "USER1234" {
		t.Errorf("Expected user code 'USER1234', got '%s'", resp.UserCode)
	}
	if resp.VerificationURI != "https://example.com/verify" {
		t.Errorf("Expected verification URI 'https://example.com/verify', got '%s'", resp.VerificationURI)
	}
	if resp.VerificationURIComplete != "https://example.com/verify?user_code=USER1234" {
		t.Errorf("Expected complete verification URI, got '%s'", resp.VerificationURIComplete)
	}
	if resp.ExpiresIn != 600 {
		t.Errorf("Expected expires_in 600, got %d", resp.ExpiresIn)
	}
	if resp.Interval != 5 {
		t.Errorf("Expected interval 5, got %d", resp.Interval)
	}
}

// TestGetDeviceCode_WithoutScope 测试不带 scope 参数
func TestGetDeviceCode_WithoutScope(t *testing.T) {
	mockClient := &MockHttpClient{
		Response: createSuccessDeviceCodeResponse(t),
	}
	util := NewOAuth2TokenUtil(mockClient)

	resp, err := util.GetDeviceCode(
		"https://example.com/oauth/device_authorization",
		"test_client_id",
		"",
	)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if resp == nil {
		t.Fatal("Expected response, got nil")
	}
}

// TestGetDeviceCode_HttpError 测试 HTTP 错误
func TestGetDeviceCode_HttpError(t *testing.T) {
	mockClient := &MockHttpClient{
		Response: createErrorResponse(http.StatusBadRequest),
	}
	util := NewOAuth2TokenUtil(mockClient)

	_, err := util.GetDeviceCode(
		"https://example.com/oauth/device_authorization",
		"test_client_id",
		"read",
	)

	if err == nil {
		t.Fatal("Expected error, got nil")
	}
}

// TestGetDeviceCode_NetworkError 测试网络错误
func TestGetDeviceCode_NetworkError(t *testing.T) {
	mockClient := &MockHttpClient{
		Error: stderrors.New("network error"),
	}
	util := NewOAuth2TokenUtil(mockClient)

	_, err := util.GetDeviceCode(
		"https://example.com/oauth/device_authorization",
		"test_client_id",
		"read",
	)

	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	if err.Error() != "network error" {
		t.Errorf("Expected 'network error', got: %v", err)
	}
}

// TestGetDeviceCode_InvalidJson 测试无效的 JSON 响应
func TestGetDeviceCode_InvalidJson(t *testing.T) {
	mockClient := &MockHttpClient{
		Response: &domain.HttpResponse{
			StatusCode: http.StatusOK,
			Headers:    map[string][]string{},
			Body:       []byte("invalid json"),
		},
	}
	util := NewOAuth2TokenUtil(mockClient)

	_, err := util.GetDeviceCode(
		"https://example.com/oauth/device_authorization",
		"test_client_id",
		"read",
	)

	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	var encodingErr *sdkerrors.EncodingError
	if !stderrors.As(err, &encodingErr) {
		t.Errorf("Expected EncodingError, got: %T", err)
	}
}

// TestGetTokenByDeviceCode_Success 测试通过 Device Code 成功获取令牌
func TestGetTokenByDeviceCode_Success(t *testing.T) {
	mockClient := &MockHttpClient{
		Response: createSuccessTokenResponse(t),
	}
	util := NewOAuth2TokenUtil(mockClient)

	resp, err := util.GetTokenByDeviceCode(
		"https://example.com/oauth/token",
		"test_client_id",
		"test_device_code",
	)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if resp == nil {
		t.Fatal("Expected response, got nil")
	}
	if resp.AccessToken != "test_access_token" {
		t.Errorf("Expected access token 'test_access_token', got '%s'", resp.AccessToken)
	}
}

// TestGetTokenByDeviceCode_HttpError 测试 HTTP 错误
func TestGetTokenByDeviceCode_HttpError(t *testing.T) {
	mockClient := &MockHttpClient{
		Response: createErrorResponse(http.StatusBadRequest),
	}
	util := NewOAuth2TokenUtil(mockClient)

	_, err := util.GetTokenByDeviceCode(
		"https://example.com/oauth/token",
		"test_client_id",
		"test_device_code",
	)

	if err == nil {
		t.Fatal("Expected error, got nil")
	}
}

// TestGetTokenByDeviceCode_NetworkError 测试网络错误
func TestGetTokenByDeviceCode_NetworkError(t *testing.T) {
	mockClient := &MockHttpClient{
		Error: stderrors.New("network error"),
	}
	util := NewOAuth2TokenUtil(mockClient)

	_, err := util.GetTokenByDeviceCode(
		"https://example.com/oauth/token",
		"test_client_id",
		"test_device_code",
	)

	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	if err.Error() != "network error" {
		t.Errorf("Expected 'network error', got: %v", err)
	}
}

// TestGetTokenByDeviceCode_InvalidJson 测试无效的 JSON 响应
func TestGetTokenByDeviceCode_InvalidJson(t *testing.T) {
	mockClient := &MockHttpClient{
		Response: &domain.HttpResponse{
			StatusCode: http.StatusOK,
			Headers:    map[string][]string{},
			Body:       []byte("invalid json"),
		},
	}
	util := NewOAuth2TokenUtil(mockClient)

	_, err := util.GetTokenByDeviceCode(
		"https://example.com/oauth/token",
		"test_client_id",
		"test_device_code",
	)

	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	var encodingErr *sdkerrors.EncodingError
	if !stderrors.As(err, &encodingErr) {
		t.Errorf("Expected EncodingError, got: %T", err)
	}
}

// TestNewOAuth2TokenUtil 测试构造函数
func TestNewOAuth2TokenUtil(t *testing.T) {
	mockClient := &MockHttpClient{}
	util := NewOAuth2TokenUtil(mockClient)

	if util == nil {
		t.Fatal("Expected util instance, got nil")
	}
	if util.httpClient != mockClient {
		t.Error("Expected httpClient to be set correctly")
	}
}
