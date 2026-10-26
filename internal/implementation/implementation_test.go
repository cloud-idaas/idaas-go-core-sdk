package implementation

import (
	"context"
	"testing"
	"time"

	"github.com/cloud-idaas/idaas-go-core-sdk/cache"
	"github.com/cloud-idaas/idaas-go-core-sdk/credential"
	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
)

// mockTestCredential is a mock implementation of IDaaSCredential for testing
type mockTestCredential struct {
	accessToken  string
	tokenType    string
	expiresIn    int64
	scope        string
	refreshToken string
}

func (m *mockTestCredential) GetAccessToken() string {
	return m.accessToken
}

func (m *mockTestCredential) GetTokenType() string {
	return m.tokenType
}

func (m *mockTestCredential) GetExpiresIn() int64 {
	return m.expiresIn
}

func (m *mockTestCredential) GetScope() string {
	return m.scope
}

func (m *mockTestCredential) GetRefreshToken() string {
	return m.refreshToken
}

// String 实现 IDaaSCredential.String (M9)，测试 mock 仅返回固定占位。
func (m *mockTestCredential) String() string {
	return "mockTestCredential"
}

func TestStaticIDaaSCredentialProvider(t *testing.T) {
	mockCred := &mockTestCredential{
		accessToken:  "test_token",
		tokenType:    "Bearer",
		expiresIn:    3600,
		scope:        "read",
		refreshToken: "refresh_token",
	}
	provider := NewStaticIDaaSCredentialProvider(mockCred)

	cred, err := provider.GetCredential()
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	if cred == nil {
		t.Fatal("Expected credential to not be nil")
	}

	if cred.GetAccessToken() != "test_token" {
		t.Errorf("Expected access token 'test_token', got '%s'", cred.GetAccessToken())
	}
}

func TestAbstractRefreshedCredentialProvider(t *testing.T) {
	// Create a mock credential
	mockCred := &mockTestCredential{
		accessToken: "test_token",
		expiresIn:   3600,
	}

	// Create a refresh function
	refreshFunc := func(ctx context.Context) (*cache.RefreshResult[credential.IDaaSCredential], error) {
		return &cache.RefreshResult[credential.IDaaSCredential]{
			Value:     mockCred,
			ExpiresAt: time.Now().Add(time.Duration(mockCred.expiresIn) * time.Second),
		}, nil
	}

	// Create the provider
	provider := NewAbstractRefreshedCredentialProvider(
		refreshFunc,
		enums.StaleValueBehaviorRefresh,
	)

	// Test GetCredential
	cred, err := provider.GetCredential()
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	if cred == nil {
		t.Fatal("Expected credential to not be nil")
	}

	if cred.GetAccessToken() != "test_token" {
		t.Errorf("Expected access token 'test_token', got '%s'", cred.GetAccessToken())
	}

	// Test Invalidate
	provider.Invalidate()
}

// TestAbstractRefreshedCredentialProvider_AllowExpiredReturnsStaleAndError:
// ALLOW 策略在过期分支返回 (cached, ErrStaleCredentialReturned),provider 层应同时
// 传递降级凭证和错误,而非丢弃 result.Value。
func TestAbstractRefreshedCredentialProvider_AllowExpiredReturnsStaleAndError(t *testing.T) {
	mockCred := &mockTestCredential{
		accessToken: "test_token",
		expiresIn:   3600,
	}

	// refreshFunc 返回一个已过期的结果，使后续 Get 进入过期分支。
	refreshFunc := func(ctx context.Context) (*cache.RefreshResult[credential.IDaaSCredential], error) {
		return &cache.RefreshResult[credential.IDaaSCredential]{
			Value:     mockCred,
			ExpiresAt: time.Now().Add(-1 * time.Hour), // 已过期
		}, nil
	}

	provider := NewAbstractRefreshedCredentialProvider(
		refreshFunc,
		enums.StaleValueBehaviorAllow,
	)

	// 建立缓存（cache miss → 同步刷新 → 存入已过期的结果）
	cred, err := provider.GetCredential()
	if err != nil {
		t.Fatalf("first GetCredential failed: %v", err)
	}
	if cred.GetAccessToken() != "test_token" {
		t.Fatalf("first token = %q, want %q", cred.GetAccessToken(), "test_token")
	}

	// ALLOW 过期：provider 应返回 (staleCred, ErrStaleCredentialReturned) 而非 (nil, err)
	cred2, err2 := provider.GetCredentialWithContext(context.Background())
	if err2 == nil {
		t.Fatal("expected error for expired ALLOW (ErrStaleCredentialReturned), got nil")
	}
	if cred2 == nil {
		t.Fatal("expected stale credential to be returned with error, got nil credential")
	}
	if cred2.GetAccessToken() != "test_token" {
		t.Errorf("expected stale token %q, got %q", "test_token", cred2.GetAccessToken())
	}
}

// TestAbstractRefreshedCredentialProvider_NilNilRefreshReturnsError:
// refreshFunc 返回 (nil, nil) 时 provider 返回错误而非 panic。
func TestAbstractRefreshedCredentialProvider_NilNilRefreshReturnsError(t *testing.T) {
	refreshFunc := func(ctx context.Context) (*cache.RefreshResult[credential.IDaaSCredential], error) {
		return nil, nil
	}

	provider := NewAbstractRefreshedCredentialProvider(
		refreshFunc,
		enums.StaleValueBehaviorBlock,
	)

	// cache miss → (nil, nil) → should return error, not panic
	cred, err := provider.GetCredential()
	if err == nil {
		t.Fatal("expected error for (nil,nil) refresh, got nil")
	}
	if cred != nil {
		t.Errorf("expected nil credential for (nil,nil) refresh, got: %v", cred)
	}
}
