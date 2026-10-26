package authentication

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloud-idaas/idaas-go-core-sdk/credential"
	"github.com/cloud-idaas/idaas-go-core-sdk/domain"
	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
	"github.com/cloud-idaas/idaas-go-core-sdk/logger"
	"github.com/cloud-idaas/idaas-go-core-sdk/oauth2"
)

// TestBoundary_EcsProvider_FetchMetadataToken_TransportError verifies that
// fetchMetadataToken on the ECS provider correctly propagates a transport-level
// error (nil response, error) from httpClient.Execute.
func TestBoundary_EcsProvider_FetchMetadataToken_TransportError(t *testing.T) {
	mock := &mockAuthHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return nil, errors.New("network error")
		},
	}
	p := NewAlibabaCloudEcsAttestedDocumentProvider(mock, "inst-123", 0)
	_, err := p.fetchMetadataToken(context.Background())
	if err == nil {
		t.Fatal("expected transport error to be propagated")
	}
}

// TestBoundary_EcsProvider_GetAttestedDocument_TransportError verifies the
// full GetAttestedDocument path propagates the transport error.
func TestBoundary_EcsProvider_GetAttestedDocument_TransportError(t *testing.T) {
	mock := &mockAuthHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return nil, errors.New("connection refused")
		},
	}
	p := NewAlibabaCloudEcsAttestedDocumentProvider(mock, "inst-123", 0)
	_, err := p.GetAttestedDocument()
	if err == nil {
		t.Fatal("expected transport error to be propagated")
	}
}

// TestBoundary_AwsEc2Provider_FetchMetadataToken_TransportError verifies that
// fetchMetadataToken on the AWS EC2 provider correctly handles a transport-level
// error. The AWS provider wraps the error in an HttpError.
func TestBoundary_AwsEc2Provider_FetchMetadataToken_TransportError(t *testing.T) {
	mock := &mockAuthHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return nil, errors.New("network timeout")
		},
	}
	p := NewAwsEc2AttestedDocumentProvider(mock, 0)
	_, err := p.fetchMetadataToken(context.Background())
	if err == nil {
		t.Fatal("expected transport error to be propagated")
	}
}

// TestBoundary_AwsEc2Provider_FetchPkcs7_TransportError verifies that
// fetchPkcs7 on the AWS EC2 provider correctly handles a transport-level
// error after a successful metadata token fetch.
func TestBoundary_AwsEc2Provider_FetchPkcs7_TransportError(t *testing.T) {
	mock := &mockAuthHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return nil, errors.New("pkcs7 network error")
		},
	}
	p := NewAwsEc2AttestedDocumentProvider(mock, 0)
	_, err := p.fetchPkcs7(context.Background(), "metadata-token")
	if err == nil {
		t.Fatal("expected transport error from fetchPkcs7")
	}
}

// TestBoundary_AwsEc2Provider_GetAttestedDocument_TransportError verifies the
// full GetAttestedDocument path propagates a transport error from fetchPkcs7.
func TestBoundary_AwsEc2Provider_GetAttestedDocument_TransportError(t *testing.T) {
	callCount := 0
	mock := &mockAuthHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			callCount++
			if callCount == 1 {
				return &domain.HttpResponse{StatusCode: 200, Body: []byte("metadata-token")}, nil
			}
			return nil, errors.New("pkcs7 transport failure")
		},
	}
	p := NewAwsEc2AttestedDocumentProvider(mock, 0)
	_, err := p.GetAttestedDocument()
	if err == nil {
		t.Fatal("expected transport error to be propagated through GetAttestedDocument")
	}
}

// newBoundaryHumanProvider creates a HumanFederatedOidcTokenProvider with a mock
// HTTP client and a temp cache path, suitable for boundary tests.
func newBoundaryHumanProvider(t *testing.T, mock *mockAuthHttpClient) *HumanFederatedOidcTokenProvider {
	t.Helper()
	tmpDir := t.TempDir()
	cachePath := filepath.Join(tmpDir, "human-cache.json")
	return &HumanFederatedOidcTokenProvider{
		clientId:                    "test-client-id",
		scope:                       DefaultScope,
		tokenEndpoint:               "https://token.example.com",
		deviceAuthorizationEndpoint: "https://device.example.com",
		localHumanCachePath:         cachePath,
		httpClient:                  mock,
		oauth2Util:                  oauth2.NewOAuth2TokenUtil(mock),
	}
}

// makeBoundaryTokenJSON marshals an IDaaSTokenResponse for mock HTTP responses.
func makeBoundaryTokenJSON(tokVal, rtVal string, expiresIn int64) []byte {
	var resp credential.IDaaSTokenResponse
	resp.AccessToken = tokVal
	resp.TokenType = "Bearer"
	resp.ExpiresIn = expiresIn
	resp.RefreshToken = rtVal
	b, _ := json.Marshal(&resp)
	return b
}

// makeBoundaryDeviceCodeJSON marshals a DeviceCodeResponse for mock HTTP responses.
func makeBoundaryDeviceCodeJSON(deviceCode string, expiresIn, interval int64) []byte {
	var resp domain.DeviceCodeResponse
	resp.DeviceCode = deviceCode
	resp.VerificationURI = "https://verify.example.com"
	resp.ExpiresIn = expiresIn
	resp.Interval = interval
	b, _ := json.Marshal(&resp)
	return b
}

// writeBoundaryCacheFile writes a token response as JSON to a cache file.
func writeBoundaryCacheFile(t *testing.T, cachePath, tokVal, rtVal string, expiresIn int64, receivedAt time.Time) {
	t.Helper()
	var token credential.IDaaSTokenResponse
	token.AccessToken = tokVal
	token.TokenType = "Bearer"
	token.ExpiresIn = expiresIn
	token.RefreshToken = rtVal
	token.ReceivedAt = receivedAt
	data, _ := json.Marshal(&token)
	if err := os.WriteFile(cachePath, data, 0o600); err != nil {
		t.Fatalf("failed to write cache file: %v", err)
	}
}

// a. Constructor test
func TestBoundary_HumanProvider_NewConstructor(t *testing.T) {
	t.Setenv("CLOUD_IDAAS_HUMAN_CREDENTIAL_CACHE_PATH", "/tmp/test-cache.json")
	mock := &mockAuthHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 200, Body: makeAuthTokenResponseBody("tok")}, nil
		},
	}
	p := NewHumanFederatedOidcTokenProvider(
		"inst-1",
		"client-123",
		"https://token.example.com",
		"https://device.example.com",
		enums.StaleValueBehaviorRefresh,
		"",
		mock,
	)
	if p == nil {
		t.Fatal("expected non-nil provider")
	}
	if p.clientId != "client-123" {
		t.Errorf("expected clientId 'client-123', got '%s'", p.clientId)
	}
	if p.tokenEndpoint != "https://token.example.com" {
		t.Errorf("unexpected tokenEndpoint: %s", p.tokenEndpoint)
	}
	if p.deviceAuthorizationEndpoint != "https://device.example.com" {
		t.Errorf("unexpected deviceAuthorizationEndpoint: %s", p.deviceAuthorizationEndpoint)
	}
	if p.localHumanCachePath != "/tmp/test-cache.json" {
		t.Errorf("expected cache path from env var, got '%s'", p.localHumanCachePath)
	}
	if p.scope != DefaultScope {
		t.Errorf("expected default scope %q, got %q", DefaultScope, p.scope)
	}
	if p.lastToken != nil {
		t.Error("expected no token on new provider")
	}
	if p.oauth2Util == nil {
		t.Error("expected non-nil oauth2Util")
	}
}

// TestBoundary_HumanProvider_DefaultCachePath_InstanceId verifies the default
// cache file name carries the instanceId dimension so the same clientId across
// different IDaaS instances does not share a cache file.
func TestBoundary_HumanProvider_DefaultCachePath_InstanceId(t *testing.T) {
	t.Setenv("HOME", "/tmp/fake-home")
	t.Setenv("CLOUD_IDAAS_HUMAN_CREDENTIAL_CACHE_PATH", "")

	// instanceId provided → file name is {instanceId}_{clientId}.json
	p := NewHumanFederatedOidcTokenProvider(
		"inst-99",
		"client-123",
		"https://token.example.com",
		"https://device.example.com",
		enums.StaleValueBehaviorRefresh,
		"",
		nil,
	)
	expected := filepath.FromSlash("/tmp/fake-home/.cloud_idaas/human-cache/inst-99_client-123.json")
	if p.localHumanCachePath != expected {
		t.Errorf("instanceId-scoped path: got %q, want %q", p.localHumanCachePath, expected)
	}

	// empty instanceId → backward-compatible {clientId}.json
	p2 := NewHumanFederatedOidcTokenProvider(
		"",
		"client-123",
		"https://token.example.com",
		"https://device.example.com",
		enums.StaleValueBehaviorRefresh,
		"",
		nil,
	)
	expected2 := filepath.FromSlash("/tmp/fake-home/.cloud_idaas/human-cache/client-123.json")
	if p2.localHumanCachePath != expected2 {
		t.Errorf("legacy path: got %q, want %q", p2.localHumanCachePath, expected2)
	}
}

// TestBoundary_HumanProvider_DefaultCachePath_NoTraversal 回归:instanceId/clientId
// 是配置值,若含路径分隔符或为路径元分量,直接拼进 filepath.Join 会穿越
// human-cache 目录(实测 instanceId="../../../../tmp/pwn" 会落到 /tmp/pwn_client.json,
// 可覆盖系统文件或落到 world-writable 目录)。sanitizeCacheSegment + base-dir 包含
// 校验必须把任意输入收敛到 baseDir 之内。
func TestBoundary_HumanProvider_DefaultCachePath_NoTraversal(t *testing.T) {
	t.Setenv("HOME", "/tmp/fake-home")
	t.Setenv("CLOUD_IDAAS_HUMAN_CREDENTIAL_CACHE_PATH", "")

	baseDir := filepath.FromSlash("/tmp/fake-home/.cloud_idaas/human-cache")
	malicious := []string{
		"../../../../tmp/pwn",
		"..",
		".",
		"../sibling",
		"/etc/passwd",
		"foo/../bar",
	}
	for _, instanceId := range malicious {
		for _, clientId := range []string{"client-123", "../../../../tmp/evil"} {
			p := NewHumanFederatedOidcTokenProvider(
				instanceId,
				clientId,
				"https://token.example.com",
				"https://device.example.com",
				enums.StaleValueBehaviorRefresh,
				"",
				nil,
			)
			cleaned := filepath.Clean(p.localHumanCachePath)
			// 必须严格落在 baseDir 之内(前缀匹配 baseDir + 分隔符)。
			if !strings.HasPrefix(cleaned+string(filepath.Separator), baseDir+string(filepath.Separator)) {
				t.Errorf("traversal escaped baseDir: instanceId=%q clientId=%q path=%q (baseDir=%q)",
					instanceId, clientId, p.localHumanCachePath, baseDir)
			}
			// 跨越目录的恶意段不得原样出现在最终路径里。
			if strings.Contains(p.localHumanCachePath, "../../../../tmp/pwn") {
				t.Errorf("malicious segment preserved verbatim: path=%q", p.localHumanCachePath)
			}
		}
	}
}

// b. tryReuseLocalCache with valid cache (far-future expiry)
func TestBoundary_TryReuseLocalCache_ValidCache(t *testing.T) {
	tmpDir := t.TempDir()
	cachePath := filepath.Join(tmpDir, "cache.json")
	writeBoundaryCacheFile(t, cachePath, "test-cached-1", "test-rt-1", 3600, time.Now())

	p := &HumanFederatedOidcTokenProvider{
		localHumanCachePath: cachePath,
	}

	result, cacheErr := p.tryReuseLocalCache(context.Background())
	if result == nil {
		t.Fatalf("expected non-nil result from tryReuseLocalCache with valid cache, err=%v", cacheErr)
	}
	if result.AccessToken != "test-cached-1" {
		t.Errorf("expected tok 'test-cached-1', got '%s'", result.AccessToken)
	}
	if result.RefreshToken != "test-rt-1" {
		t.Errorf("expected rt 'test-rt-1', got '%s'", result.RefreshToken)
	}
}

// c. tryReuseLocalCache with non-existent cache file
func TestBoundary_TryReuseLocalCache_NoCacheFile(t *testing.T) {
	p := &HumanFederatedOidcTokenProvider{
		localHumanCachePath: filepath.Join(t.TempDir(), "nonexistent.json"),
	}

	result, _ := p.tryReuseLocalCache(context.Background())
	if result != nil {
		t.Errorf("expected nil result when cache file does not exist, got %+v", result)
	}
}

// d. tryReuseLocalCache with invalid JSON
func TestBoundary_TryReuseLocalCache_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	cachePath := filepath.Join(tmpDir, "cache.json")
	if err := os.WriteFile(cachePath, []byte("{invalid json}"), 0o600); err != nil {
		t.Fatalf("failed to write cache file: %v", err)
	}

	p := &HumanFederatedOidcTokenProvider{
		localHumanCachePath: cachePath,
	}

	result, _ := p.tryReuseLocalCache(context.Background())
	if result != nil {
		t.Errorf("expected nil result for invalid JSON cache, got %+v", result)
	}
}

// e. tryReuseLocalCache with expiring token + refresh via mock HTTP
func TestBoundary_TryReuseLocalCache_ExpiringTokenWithRefresh(t *testing.T) {
	tmpDir := t.TempDir()
	cachePath := filepath.Join(tmpDir, "cache.json")

	// ExpiresIn=100, ReceivedAt = now - 90s → token expires in ~10s
	// threshold = 100/3 ≈ 33s, expiryTime = now+10 < now+33 → WillSoonExpire = true
	writeBoundaryCacheFile(t, cachePath, "test-old-1", "test-old-rt-1", 100, time.Now().Add(-90*time.Second))

	mock := &mockAuthHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{
				StatusCode: 200,
				Body:       makeBoundaryTokenJSON("test-refreshed-1", "test-new-rt-1", 3600),
			}, nil
		},
	}

	p := &HumanFederatedOidcTokenProvider{
		localHumanCachePath: cachePath,
		tokenEndpoint:       "https://token.example.com",
		clientId:            "test-client",
		httpClient:          mock,
		oauth2Util:          oauth2.NewOAuth2TokenUtil(mock),
	}

	result, cacheErr := p.tryReuseLocalCache(context.Background())
	if result == nil {
		t.Fatalf("expected non-nil result from tryReuseLocalCache with refresh, err=%v", cacheErr)
	}
	if result.AccessToken != "test-refreshed-1" {
		t.Errorf("expected refreshed tok 'test-refreshed-1', got '%s'", result.AccessToken)
	}
	if result.RefreshToken != "test-new-rt-1" {
		t.Errorf("expected new rt 'test-new-rt-1', got '%s'", result.RefreshToken)
	}

	// Verify cache file was overwritten with the refreshed value
	cacheData, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatalf("failed to read cache file after refresh: %v", err)
	}
	var readBack credential.IDaaSTokenResponse
	if err := json.Unmarshal(cacheData, &readBack); err != nil {
		t.Fatalf("failed to unmarshal cache: %v", err)
	}
	if readBack.AccessToken != "test-refreshed-1" {
		t.Errorf("expected cache to contain refreshed tok, got '%s'", readBack.AccessToken)
	}
}

// g. refresh_token preservation when server omits refresh_token in cache-reuse path.
// Cache has a refresh_token; mock token endpoint returns a refreshed token WITHOUT refresh_token.
// The returned token should preserve the old refresh_token so subsequent refreshes don't
// fall back to device flow.
func TestBoundary_TryReuseLocalCache_RefreshTokenPreserved(t *testing.T) {
	tmpDir := t.TempDir()
	cachePath := filepath.Join(tmpDir, "cache.json")

	// ExpiresIn=100, ReceivedAt = now - 90s → token expires in ~10s → WillSoonExpire = true
	writeBoundaryCacheFile(t, cachePath, "old-tok", "old-rt", 100, time.Now().Add(-90*time.Second))

	mock := &mockAuthHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			// Return a refreshed token with access_token but NO refresh_token
			return &domain.HttpResponse{
				StatusCode: 200,
				Body:       makeBoundaryTokenJSON("refreshed-tok", "", 3600),
			}, nil
		},
	}

	p := &HumanFederatedOidcTokenProvider{
		localHumanCachePath: cachePath,
		tokenEndpoint:       "https://token.example.com",
		clientId:            "test-client",
		httpClient:          mock,
		oauth2Util:          oauth2.NewOAuth2TokenUtil(mock),
	}

	result, err := p.tryReuseLocalCache(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result from tryReuseLocalCache")
	}
	if result.AccessToken != "refreshed-tok" {
		t.Errorf("expected 'refreshed-tok', got '%s'", result.AccessToken)
	}
	// server omitted refresh_token (empty in response), old one should be preserved
	if result.RefreshToken != "old-rt" {
		t.Errorf("expected old refresh_token 'old-rt' to be preserved, got '%s'", result.RefreshToken)
	}
}

// h. cache-reuse invalid_grant → returns (nil, nil) → caller falls back to device flow.
func TestBoundary_TryReuseLocalCache_InvalidGrantReturnsNilNoErr(t *testing.T) {
	tmpDir := t.TempDir()
	cachePath := filepath.Join(tmpDir, "cache.json")

	writeBoundaryCacheFile(t, cachePath, "old-tok", "old-rt", 100, time.Now().Add(-90*time.Second))

	mock := &mockAuthHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{
				StatusCode: 400,
				Body:       []byte(`{"error":"invalid_grant","error_description":"refresh token revoked"}`),
			}, nil
		},
	}

	p := &HumanFederatedOidcTokenProvider{
		localHumanCachePath: cachePath,
		tokenEndpoint:       "https://token.example.com",
		clientId:            "test-client",
		httpClient:          mock,
		oauth2Util:          oauth2.NewOAuth2TokenUtil(mock),
	}

	result, err := p.tryReuseLocalCache(context.Background())
	if result != nil {
		t.Errorf("expected nil result for invalid_grant, got %+v", result)
	}
	if err != nil {
		t.Errorf("expected nil error for invalid_grant (caller falls back to device flow), got: %v", err)
	}
}

// i. cache-reuse transient error → returns (nil, err) → caller propagates, no device flow.
func TestBoundary_TryReuseLocalCache_TransientErrPropagates(t *testing.T) {
	tmpDir := t.TempDir()
	cachePath := filepath.Join(tmpDir, "cache.json")

	writeBoundaryCacheFile(t, cachePath, "old-tok", "old-rt", 100, time.Now().Add(-90*time.Second))

	mock := &mockAuthHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return nil, errors.New("connection reset by peer")
		},
	}

	p := &HumanFederatedOidcTokenProvider{
		localHumanCachePath: cachePath,
		tokenEndpoint:       "https://token.example.com",
		clientId:            "test-client",
		httpClient:          mock,
		oauth2Util:          oauth2.NewOAuth2TokenUtil(mock),
	}

	result, err := p.tryReuseLocalCache(context.Background())
	if result != nil {
		t.Errorf("expected nil result for transient error, got %+v", result)
	}
	if err == nil {
		t.Fatal("expected non-nil error for transient failure (should propagate, not fall back to device flow)")
	}
}

// f. getTokenWithDeviceAuthorization — success on first poll
func TestBoundary_GetTokenWithDeviceAuthorization_SuccessFirstPoll(t *testing.T) {
	callCount := 0
	mock := &mockAuthHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			callCount++
			if callCount == 1 {
				return &domain.HttpResponse{
					StatusCode: 200,
					Body:       makeBoundaryDeviceCodeJSON("dev-123", 5, 1),
				}, nil
			}
			return &domain.HttpResponse{
				StatusCode: 200,
				Body:       makeBoundaryTokenJSON("test-device-flow", "test-rt-123", 3600),
			}, nil
		},
	}

	p := &HumanFederatedOidcTokenProvider{
		clientId:                    "test-client",
		tokenEndpoint:               "https://token.example.com",
		deviceAuthorizationEndpoint: "https://device.example.com",
		httpClient:                  mock,
		oauth2Util:                  oauth2.NewOAuth2TokenUtil(mock),
	}

	token, err := p.getTokenWithDeviceAuthorization(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token.AccessToken != "test-device-flow" {
		t.Errorf("expected 'test-device-flow', got '%s'", token.AccessToken)
	}
	if callCount < 2 {
		t.Errorf("expected at least 2 HTTP calls (device code + poll), got %d", callCount)
	}
}

// f2. getTokenWithDeviceAuthorization — authorization_pending then success
func TestBoundary_GetTokenWithDeviceAuthorization_PendingThenSuccess(t *testing.T) {
	callCount := 0
	mock := &mockAuthHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			callCount++
			if callCount == 1 {
				return &domain.HttpResponse{
					StatusCode: 200,
					Body:       makeBoundaryDeviceCodeJSON("dev-456", 10, 1),
				}, nil
			}
			if callCount == 2 {
				return &domain.HttpResponse{
					StatusCode: 400,
					Body:       []byte(`{"error":"authorization_pending"}`),
				}, nil
			}
			return &domain.HttpResponse{
				StatusCode: 200,
				Body:       makeBoundaryTokenJSON("test-pending-ok", "test-rt-456", 3600),
			}, nil
		},
	}

	p := &HumanFederatedOidcTokenProvider{
		clientId:                    "test-client",
		tokenEndpoint:               "https://token.example.com",
		deviceAuthorizationEndpoint: "https://device.example.com",
		httpClient:                  mock,
		oauth2Util:                  oauth2.NewOAuth2TokenUtil(mock),
	}

	token, err := p.getTokenWithDeviceAuthorization(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token.AccessToken != "test-pending-ok" {
		t.Errorf("expected 'test-pending-ok', got '%s'", token.AccessToken)
	}
}

// g. writeToLocalCache — verify file is written
func TestBoundary_WriteToLocalCache(t *testing.T) {
	tmpDir := t.TempDir()
	cachePath := filepath.Join(tmpDir, "sub", "cache.json")

	p := &HumanFederatedOidcTokenProvider{
		localHumanCachePath: cachePath,
	}

	var token credential.IDaaSTokenResponse
	token.AccessToken = "test-write-tok"
	token.TokenType = "Bearer"
	token.ExpiresIn = 3600
	token.RefreshToken = "test-write-rt"
	token.ReceivedAt = time.Now()

	p.writeToLocalCache(&token)

	data, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatalf("expected cache file to be written: %v", err)
	}

	var readBack credential.IDaaSTokenResponse
	if err := json.Unmarshal(data, &readBack); err != nil {
		t.Fatalf("failed to unmarshal written cache: %v", err)
	}
	if readBack.AccessToken != "test-write-tok" {
		t.Errorf("expected 'test-write-tok', got '%s'", readBack.AccessToken)
	}
	if readBack.RefreshToken != "test-write-rt" {
		t.Errorf("expected 'test-write-rt', got '%s'", readBack.RefreshToken)
	}
}

// h. Getter tests
func TestBoundary_HumanProvider_Getters(t *testing.T) {
	mock := &mockAuthHttpClient{}
	p := &HumanFederatedOidcTokenProvider{
		clientId:                    "getter-client-id",
		tokenEndpoint:               "https://token.getter.com",
		deviceAuthorizationEndpoint: "https://device.getter.com",
		httpClient:                  mock,
	}

	if p.GetClientId() != "getter-client-id" {
		t.Errorf("GetClientId() = %q, want %q", p.GetClientId(), "getter-client-id")
	}
	if p.GetTokenEndpoint() != "https://token.getter.com" {
		t.Errorf("GetTokenEndpoint() = %q, want %q", p.GetTokenEndpoint(), "https://token.getter.com")
	}
	if p.GetDeviceAuthorizationEndpoint() != "https://device.getter.com" {
		t.Errorf("GetDeviceAuthorizationEndpoint() = %q, want %q",
			p.GetDeviceAuthorizationEndpoint(), "https://device.getter.com")
	}
}

// i. getCredential — full device authorization flow via mock HTTP
func TestBoundary_GetCredential_FullDeviceAuthFlow(t *testing.T) {
	callCount := 0
	mock := &mockAuthHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			callCount++
			if callCount == 1 {
				return &domain.HttpResponse{
					StatusCode: 200,
					Body:       makeBoundaryDeviceCodeJSON("dev-full-flow", 5, 1),
				}, nil
			}
			return &domain.HttpResponse{
				StatusCode: 200,
				Body:       makeBoundaryTokenJSON("test-full-flow", "test-full-rt", 3600),
			}, nil
		},
	}
	p := newBoundaryHumanProvider(t, mock)

	cred, err := p.GetCredentialWithContext(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred == nil {
		t.Fatal("expected non-nil credential")
	}
	if cred.GetAccessToken() != "test-full-flow" {
		t.Errorf("expected 'test-full-flow', got '%s'", cred.GetAccessToken())
	}

	// Verify cache file was written
	if _, err := os.Stat(p.localHumanCachePath); err != nil {
		t.Errorf("expected cache file to be written: %v", err)
	}

	// Verify lastToken is populated
	if p.lastToken == nil || p.lastToken.AccessToken != "test-full-flow" {
		t.Errorf("expected lastToken 'test-full-flow', got %+v", p.lastToken)
	}
}

// k. getCredential — previous token with empty refresh token falls back to device flow
//
// 把"empty refresh_token → 报错"改为"empty refresh_token → 回退 device flow"。
// 此测试验证回退路径:mock device 授权端点 + 轮询端点,断言回退成功返回新 token,
// 而非走 refresh_token 刷新(空 token 无法刷新)。
func TestBoundary_GetCredential_PreviousToken_EmptyRefreshToken(t *testing.T) {
	callCount := 0
	mock := &mockAuthHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			callCount++
			if callCount == 1 {
				// device authorization endpoint → 返回 device code
				return &domain.HttpResponse{
					StatusCode: 200,
					Body:       makeBoundaryDeviceCodeJSON("dev-fallback", 5, 1),
				}, nil
			}
			// 第一次轮询即返回 token(expiresIn=5,interval=1,轮询一次后命中)
			return &domain.HttpResponse{
				StatusCode: 200,
				Body:       makeBoundaryTokenJSON("test-fallback-tok", "test-fallback-rt", 3600),
			}, nil
		},
	}
	p := newBoundaryHumanProvider(t, mock)

	// 已有 token 但 refresh_token 为空 → 无法走刷新,应回退 device flow。
	var cachedVal credential.IDaaSTokenResponse
	cachedVal.AccessToken = "test-some-tok"
	cachedVal.RefreshToken = "" // empty
	p.lastToken = &cachedVal

	cred, err := p.GetCredentialWithContext(context.Background())
	if err != nil {
		t.Fatalf("expected fallback to device flow to succeed, got error: %v", err)
	}
	if cred == nil {
		t.Fatal("expected non-nil credential from device flow fallback")
	}
	if cred.GetAccessToken() != "test-fallback-tok" {
		t.Errorf("expected 'test-fallback-tok' from device flow, got '%s'", cred.GetAccessToken())
	}
	if callCount < 2 {
		t.Errorf("expected at least 2 HTTP calls (device code + poll), got %d", callCount)
	}
	// 回退成功后 lastToken 应更新为新 token,后续走正常 refresh 路径。
	if p.lastToken == nil || p.lastToken.AccessToken != "test-fallback-tok" {
		t.Errorf("expected lastToken updated to 'test-fallback-tok', got %+v", p.lastToken)
	}
}

// l. getCredential — previous token with refresh token (refresh success)
func TestBoundary_GetCredential_PreviousToken_RefreshSuccess(t *testing.T) {
	mock := &mockAuthHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{
				StatusCode: 200,
				Body:       makeBoundaryTokenJSON("test-refreshed-cred", "test-new-rt-2", 3600),
			}, nil
		},
	}
	p := newBoundaryHumanProvider(t, mock)

	var cachedVal credential.IDaaSTokenResponse
	cachedVal.AccessToken = "test-old-tok-2"
	cachedVal.RefreshToken = "test-valid-rt-2"
	p.lastToken = &cachedVal

	cred, err := p.GetCredentialWithContext(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred.GetAccessToken() != "test-refreshed-cred" {
		t.Errorf("expected 'test-refreshed-cred', got '%s'", cred.GetAccessToken())
	}
}

// suppress unused import warnings
var _ = enums.HttpMethodGet

// --- sanitizeCacheSegment 单元回归 ---
//
// sanitizeCacheSegment 是 #2 路径穿越修复的核心:把 instanceId/clientId 中含路径分隔符
// 或为路径元分量("." "..")的输入收敛为 sha256 前 16 字符(前缀 "id_"),合法输入原样返回。
// 这里逐场景断言它的边界行为,防回归(比如有人误把判断改成 strings.Contains(s, "..")
// 会把合法的 "foo..bar" 也收敛,破坏已落盘缓存文件名)。
func TestSanitizeCacheSegment(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		sanitized   bool // 期望被收敛(sha256)
		passThrough bool // 期望原样返回
	}{
		{"空串", "", true, false},
		{"路径元分量点", ".", true, false},
		{"路径元分量双点", "..", true, false},
		{"含正斜杠", "foo/bar", true, false},
		{"含反斜杠", `foo\bar`, true, false},
		{"绝对路径", "/etc/passwd", true, false},
		{"穿越段", "../../../../tmp/pwn", true, false},
		{"合法普通 id", "inst-99", false, true},
		{"合法含点子串(非元分量)", "foo..bar", false, true},
		{"合法含连字符", "client-123", false, true},
		{"合法含空格", "my instance", false, true},
		{"合法纯数字", "1234567890", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeCacheSegment(tt.input)
			if tt.passThrough {
				if got != tt.input {
					t.Errorf("合法输入应原样返回: input=%q got=%q", tt.input, got)
				}
			}
			if tt.sanitized {
				if !strings.HasPrefix(got, "id_") {
					t.Errorf("恶意输入应收敛为 id_ 前缀: input=%q got=%q", tt.input, got)
				}
				// "id_" + 16 hex = 19 字符
				if len(got) != 19 {
					t.Errorf("收敛结果应为 19 字符(id_+16hex): input=%q got=%q len=%d", tt.input, got, len(got))
				}
				// 收敛后不得保留原恶意输入的可穿越段
				if tt.input != "" && strings.Contains(got, tt.input) && tt.input != "." && tt.input != ".." {
					// 仅当原输入含路径分隔符时才算泄漏;合法子串已被 passThrough 覆盖。
					if strings.ContainsAny(tt.input, "/\\") {
						t.Errorf("收敛结果泄漏原输入: input=%q got=%q", tt.input, got)
					}
				}
			}
		})
	}

	// 不同恶意输入必须产生不同输出(避免覆盖:两个不同攻击值不能落到同一文件名)
	a := sanitizeCacheSegment("foo/bar")
	b := sanitizeCacheSegment("foo\\bar")
	c := sanitizeCacheSegment("../pwn")
	if a == b || a == c || b == c {
		t.Errorf("不同恶意输入不应收敛到同一文件名: a=%s b=%s c=%s", a, b, c)
	}
}

// TestBoundary_HumanProvider_DefaultCachePath_EnvOverridePassthrough 验证环境变量
// 覆盖路径时不经过 sanitize——这是有意的信任边界差异:
// CLOUD_IDAAS_HUMAN_CREDENTIAL_CACHE_PATH 由运维设置,运维对文件系统已有完整控制权,
// 不属于"不可信配置值"维度。此测试固化该语义,避免有人误把 env 路径也做 sanitize
// 而破坏运维指定的自定义路径。
func TestBoundary_HumanProvider_DefaultCachePath_EnvOverridePassthrough(t *testing.T) {
	t.Setenv("CLOUD_IDAAS_HUMAN_CREDENTIAL_CACHE_PATH", "/opt/custom/path/cache.json")
	p := NewHumanFederatedOidcTokenProvider(
		"../../../../tmp/pwn", // 即使 instanceId 恶意,env 覆盖也优先生效
		"client-123",
		"https://token.example.com",
		"https://device.example.com",
		enums.StaleValueBehaviorRefresh,
		"",
		nil,
	)
	if p.localHumanCachePath != "/opt/custom/path/cache.json" {
		t.Errorf("env 覆盖路径应原样生效(运维信任边界),got %q", p.localHumanCachePath)
	}
}

// TestBoundary_HumanProvider_FullFlow_MaliciousInstanceId 集成式回归:
// 用真实构造函数喂入恶意 instanceId(穿越段),走完整 device flow(mock HTTP),
// 验证缓存文件最终落在 baseDir 之内而非 /tmp/pwn_client-123.json。
// 这条路径串联 sanitizeCacheSegment + base-dir 包含校验 + writeToLocalCache,
// 任一环回归都会让缓存文件逃出 baseDir。
func TestBoundary_HumanProvider_FullFlow_MaliciousInstanceId(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	t.Setenv("CLOUD_IDAAS_HUMAN_CREDENTIAL_CACHE_PATH", "")

	callCount := 0
	mock := &mockAuthHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			callCount++
			if callCount == 1 {
				return &domain.HttpResponse{
					StatusCode: 200,
					Body:       makeBoundaryDeviceCodeJSON("dev-malicious", 5, 1),
				}, nil
			}
			return &domain.HttpResponse{
				StatusCode: 200,
				Body:       makeBoundaryTokenJSON("tok-malicious", "rt-malicious", 3600),
			}, nil
		},
	}
	// 恶意 instanceId:在修复前会让缓存文件落到 /tmp/pwn_client-123.json
	p := NewHumanFederatedOidcTokenProvider(
		"../../../../tmp/pwn",
		"client-123",
		"https://token.example.com",
		"https://device.example.com",
		enums.StaleValueBehaviorRefresh,
		"",
		mock,
	)

	cred, err := p.GetCredentialWithContext(context.Background())
	if err != nil {
		t.Fatalf("full flow should succeed: %v", err)
	}
	if cred.GetAccessToken() != "tok-malicious" {
		t.Errorf("token mismatch: got %s", cred.GetAccessToken())
	}

	baseDir := filepath.Join(tmpHome, ".cloud_idaas", "human-cache")
	cleaned := filepath.Clean(p.localHumanCachePath)
	// 必须严格落在 baseDir 之内
	if !strings.HasPrefix(cleaned+string(filepath.Separator), baseDir+string(filepath.Separator)) {
		t.Errorf("缓存文件逃出 baseDir: path=%q baseDir=%q", p.localHumanCachePath, baseDir)
	}
	// 穿越段不得原样保留
	if strings.Contains(p.localHumanCachePath, "../../../../tmp/pwn") {
		t.Errorf("恶意穿越段被原样保留: path=%q", p.localHumanCachePath)
	}
	// 缓存文件应已被写入(在 baseDir 之下)
	if _, err := os.Stat(p.localHumanCachePath); err != nil {
		t.Errorf("缓存文件应已写入 baseDir 之下: %v (path=%q)", err, p.localHumanCachePath)
	}
	// /tmp/pwn_client-123.json 不应被创建(穿越目标)
	if _, err := os.Stat("/tmp/pwn_client-123.json"); err == nil {
		t.Errorf("穿越目标 /tmp/pwn_client-123.json 被创建,路径穿越修复失效")
	}
}

// recordingDeviceLogger 记录所有 logger 调用(线程安全),用于断言 device flow
// 不再把 user_code 写进结构化日志。
type recordingDeviceLogger struct {
	mu     sync.Mutex
	infos  []string
	warns  []string
	errors []string
}

func (r *recordingDeviceLogger) Debug(ctx context.Context, msg string, kv ...interface{}) {}
func (r *recordingDeviceLogger) Info(ctx context.Context, msg string, kv ...interface{}) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.infos = append(r.infos, msg)
}
func (r *recordingDeviceLogger) Warn(ctx context.Context, msg string, kv ...interface{}) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.warns = append(r.warns, msg)
}
func (r *recordingDeviceLogger) Error(ctx context.Context, msg string, kv ...interface{}) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.errors = append(r.errors, msg)
}
func (r *recordingDeviceLogger) containsInInfos(sub string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, m := range r.infos {
		if strings.Contains(m, sub) {
			return true
		}
	}
	return false
}

// TestDeviceFlow_UserCode_RoutedToHandler_NotLogger 验证:
// user_code 经宿主 handler 展示给最终用户,不进结构化日志(message 与 kv 均不含
// user_code 本体)。同时 IdP 返回 verification_uri_complete(含内嵌 code)时,
// 该完整 URL 也不进日志(避免 user_code 经 URL 进日志被他人抢在合法用户前完成授权)。
func TestDeviceFlow_UserCode_RoutedToHandler_NotLogger(t *testing.T) {
	const (
		deviceCode  = "dev-456"
		userCode    = "ABC-123-XYZ" // RFC 8628 一次性展示码,绝不应进结构化日志
		completeURI = "https://verify.example.com?code=" + userCode
	)

	mock := &mockAuthHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			// device-authorization endpoint 首请求返回 verification_uri_complete(内嵌 user_code);
			// token endpoint 轮询请求返回成功令牌。
			if strings.Contains(req.URL, "device.example.com") {
				var dcResp domain.DeviceCodeResponse
				dcResp.DeviceCode = deviceCode
				dcResp.VerificationURIComplete = completeURI
				dcResp.VerificationURI = "https://verify.example.com"
				dcResp.UserCode = userCode
				dcResp.ExpiresIn = 5
				dcResp.Interval = 1
				b, _ := json.Marshal(&dcResp)
				return &domain.HttpResponse{StatusCode: 200, Body: b}, nil
			}
			return &domain.HttpResponse{
				StatusCode: 200,
				Body:       makeBoundaryTokenJSON("tok-handler-flow", "rt-1", 3600),
			}, nil
		},
	}

	var (
		gotURI    string
		gotCode   string
		handlerMu sync.Mutex
	)
	handler := func(uri, code string) {
		handlerMu.Lock()
		gotURI = uri
		gotCode = code
		handlerMu.Unlock()
	}

	p := &HumanFederatedOidcTokenProvider{
		clientId:                    "test-client",
		tokenEndpoint:               "https://token.example.com",
		deviceAuthorizationEndpoint: "https://device.example.com",
		httpClient:                  mock,
		oauth2Util:                  oauth2.NewOAuth2TokenUtil(mock),
		userCodeHandler:             handler,
	}

	rec := &recordingDeviceLogger{}
	prev := logger.Default()
	logger.SetDefault(rec)
	defer logger.SetDefault(prev)

	token, err := p.getTokenWithDeviceAuthorization(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = token

	// handler 收到 verification_uri_complete(优先)与 user_code:
	// user_code 必须经 handler 展示给用户(否则用户无法完成授权)。
	handlerMu.Lock()
	if gotURI != completeURI {
		t.Errorf("handler verificationURI = %q, want %q (verification_uri_complete 优先)",
			gotURI, completeURI)
	}
	if gotCode != userCode {
		t.Errorf("handler userCode = %q, want %q", gotCode, userCode)
	}
	handlerMu.Unlock()

	// user_code 本体绝不应出现在任何 logger 调用的 message 里(无论 kv 是否脱敏):
	// 改调 handler,日志只剩非 code 消息。
	if rec.containsInInfos(userCode) {
		t.Errorf("user_code %q leaked into logger Info message; must be routed to handler only", userCode)
	}
	// verification_uri_complete 含内嵌 user_code,同样不应进日志(防止经 URL 泄漏 code)。
	if rec.containsInInfos(completeURI) {
		t.Errorf("verification_uri_complete (contains user_code) leaked into logger; must stay out of logs: %s", completeURI)
	}
	// 应有一条非 code 的"已收到 device code"消息(event=human.device_code)。
	if !rec.containsInInfos("device authorization code received") {
		t.Error("expected non-code 'device authorization code received' Info message; got none")
	}
}

// TestDeviceFlow_VerificationURIComplete_NotLogged 验证:即便 IdP 只返回
// bare verification_uri(无 verification_uri_complete),user_code 仍经 handler 展示、
// 不进日志;且 bare verification_uri 走 handler 而非被 SDK 主动 OpenBrowser
// (库边界 side-effect 已移交宿主)。
func TestDeviceFlow_VerificationURIComplete_NotLogged(t *testing.T) {
	const (
		deviceCode = "dev-789"
		userCode   = "Q-Z9-7WX"
		bareURI    = "https://verify.example.com"
	)

	mock := &mockAuthHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			if strings.Contains(req.URL, "device.example.com") {
				var dcResp domain.DeviceCodeResponse
				dcResp.DeviceCode = deviceCode
				// 仅返回 verification_uri(无 complete),用户须手输 user_code。
				dcResp.VerificationURI = bareURI
				dcResp.UserCode = userCode
				dcResp.ExpiresIn = 5
				dcResp.Interval = 1
				b, _ := json.Marshal(&dcResp)
				return &domain.HttpResponse{StatusCode: 200, Body: b}, nil
			}
			return &domain.HttpResponse{
				StatusCode: 200,
				Body:       makeBoundaryTokenJSON("tok-bare-flow", "rt-2", 3600),
			}, nil
		},
	}

	var (
		gotURI, gotCode string
		handlerMu       sync.Mutex
	)
	handler := func(uri, code string) {
		handlerMu.Lock()
		gotURI = uri
		gotCode = code
		handlerMu.Unlock()
	}

	p := &HumanFederatedOidcTokenProvider{
		clientId:                    "test-client",
		tokenEndpoint:               "https://token.example.com",
		deviceAuthorizationEndpoint: "https://device.example.com",
		httpClient:                  mock,
		oauth2Util:                  oauth2.NewOAuth2TokenUtil(mock),
		userCodeHandler:             handler,
	}

	rec := &recordingDeviceLogger{}
	prev := logger.Default()
	logger.SetDefault(rec)
	defer logger.SetDefault(prev)

	if _, err := p.getTokenWithDeviceAuthorization(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	handlerMu.Lock()
	// 无 verification_uri_complete 时 handler 收到 bare verification_uri。
	if gotURI != bareURI {
		t.Errorf("handler verificationURI = %q, want bare %q", gotURI, bareURI)
	}
	if gotCode != userCode {
		t.Errorf("handler userCode = %q, want %q (must be displayed even without verification_uri_complete)",
			gotCode, userCode)
	}
	handlerMu.Unlock()

	// user_code 不进任何日志 message。
	if rec.containsInInfos(userCode) {
		t.Errorf("user_code %q leaked into logger Info message", userCode)
	}
	// 旧实现曾把 user_code 拼进 "enter this code in the verification page: <code>" 消息,
	// 该消息文本不应再出现(改调 handler)。
	if rec.containsInInfos("enter this code") {
		t.Error("legacy 'enter this code' message still present; should be replaced by handler call")
	}
}
