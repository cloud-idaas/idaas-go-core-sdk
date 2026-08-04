package implementation

import (
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
	refreshFunc := func() (*cache.RefreshResult[credential.IDaaSCredential], error) {
		return &cache.RefreshResult[credential.IDaaSCredential]{
			Value:     mockCred,
			ExpiresAt: time.Now().Add(time.Duration(mockCred.expiresIn) * time.Second),
		}, nil
	}

	// Create the provider
	provider := NewAbstractRefreshedCredentialProvider(
		refreshFunc,
		enums.StaleValueBehaviorRefresh,
		5*time.Minute,
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
