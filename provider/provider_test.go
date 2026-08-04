package provider

import (
	"testing"

	"github.com/cloud-idaas/idaas-go-core-sdk/credential"
)

// mockCredential is a mock implementation of IDaaSCredential for testing
type mockCredential struct {
	accessToken  string
	tokenType    string
	expiresIn    int64
	scope        string
	refreshToken string
}

func (m *mockCredential) GetAccessToken() string {
	return m.accessToken
}

func (m *mockCredential) GetTokenType() string {
	return m.tokenType
}

func (m *mockCredential) GetExpiresIn() int64 {
	return m.expiresIn
}

func (m *mockCredential) GetScope() string {
	return m.scope
}

func (m *mockCredential) GetRefreshToken() string {
	return m.refreshToken
}

func TestIDaaSCredentialProviderInterface(t *testing.T) {
	// Verify that the interface is properly defined
	var _ credential.IDaaSCredential = (*mockCredential)(nil)
}

func TestIDaaSTokenExchangeCredentialProviderInterface(t *testing.T) {
	// Verify that the interface is properly defined
	// This test ensures the interface compiles correctly
	var provider IDaaSTokenExchangeCredentialProvider
	if provider != nil {
		t.Error("Expected nil provider")
	}
}

func TestRefreshCredentialProviderInterface(t *testing.T) {
	// Verify that the interface is properly defined
	var provider RefreshCredentialProvider[credential.IDaaSCredential]
	if provider != nil {
		t.Error("Expected nil provider")
	}
}

func TestJwtClientAssertionProviderInterface(t *testing.T) {
	// Verify that the interface is properly defined
	var provider JwtClientAssertionProvider
	if provider != nil {
		t.Error("Expected nil provider")
	}
}

func TestPkcs7AttestedDocumentProviderInterface(t *testing.T) {
	// Verify that the interface is properly defined
	var provider Pkcs7AttestedDocumentProvider
	if provider != nil {
		t.Error("Expected nil provider")
	}
}

func TestOidcTokenProviderInterface(t *testing.T) {
	// Verify that the interface is properly defined
	var provider OidcTokenProvider
	if provider != nil {
		t.Error("Expected nil provider")
	}
}

func TestPluginCredentialProviderInterface(t *testing.T) {
	// Verify that the interface is properly defined
	var provider PluginCredentialProvider
	if provider != nil {
		t.Error("Expected nil provider")
	}
}
