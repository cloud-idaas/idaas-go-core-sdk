package oauth2

import (
	"context"
	stderrors "errors"
	"net/http"
	"testing"

	"github.com/cloud-idaas/idaas-go-core-sdk/domain"
)

func TestGetTokenByClientCredentialsJwtAssertion_Success(t *testing.T) {
	mockClient := &MockHttpClient{Response: createSuccessTokenResponse(t)}
	util := NewOAuth2TokenUtil(mockClient)

	resp, err := util.GetTokenByClientCredentialsJwtAssertion(
		"https://example.com/oauth/token",
		"client_id",
		"jwt_assertion",
		"read write",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || resp.AccessToken != "test_access_token" {
		t.Errorf("unexpected response: %+v", resp)
	}
}

func TestGetTokenByClientCredentialsJwtAssertion_WithoutScope(t *testing.T) {
	mockClient := &MockHttpClient{Response: createSuccessTokenResponse(t)}
	util := NewOAuth2TokenUtil(mockClient)

	resp, err := util.GetTokenByClientCredentialsJwtAssertion(
		"https://example.com/oauth/token", "cid", "assertion", "",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response, got nil")
	}
}

func TestGetTokenByClientCredentialsJwtAssertion_HttpError(t *testing.T) {
	mockClient := &MockHttpClient{Response: createErrorResponse(http.StatusBadRequest)}
	util := NewOAuth2TokenUtil(mockClient)

	_, err := util.GetTokenByClientCredentialsJwtAssertion(
		"https://example.com/oauth/token", "cid", "assertion", "read",
	)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestGetTokenByX509JwtBearer_Success(t *testing.T) {
	mockClient := &MockHttpClient{Response: createSuccessTokenResponse(t)}
	util := NewOAuth2TokenUtil(mockClient)

	resp, err := util.GetTokenByX509JwtBearer(
		"https://example.com/oauth/token",
		"client_id",
		"assertion",
		"cert_pem",
		"chain_pem",
		"fed_cred_name",
		"read",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || resp.AccessToken != "test_access_token" {
		t.Errorf("unexpected response: %+v", resp)
	}
}

func TestGetTokenByX509JwtBearer_WithoutOptionalScope(t *testing.T) {
	mockClient := &MockHttpClient{Response: createSuccessTokenResponse(t)}
	util := NewOAuth2TokenUtil(mockClient)

	resp, err := util.GetTokenByX509JwtBearer(
		"https://example.com/oauth/token",
		"cid", "assertion", "cert", "chain", "fed", "",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response, got nil")
	}
}

func TestGetTokenByX509JwtBearer_HttpError(t *testing.T) {
	mockClient := &MockHttpClient{Response: createErrorResponse(http.StatusUnauthorized)}
	util := NewOAuth2TokenUtil(mockClient)

	_, err := util.GetTokenByX509JwtBearer(
		"https://example.com/oauth/token", "cid", "assertion", "cert", "chain", "fed", "read",
	)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestGetTokenWithPKCS7AttestedDocument_Success(t *testing.T) {
	mockClient := &MockHttpClient{Response: createSuccessTokenResponse(t)}
	util := NewOAuth2TokenUtil(mockClient)

	resp, err := util.GetTokenWithPKCS7AttestedDocument(
		"https://example.com/oauth/token",
		"client_id",
		"fed_cred",
		"pkcs7_doc",
		"read",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || resp.AccessToken != "test_access_token" {
		t.Errorf("unexpected response: %+v", resp)
	}
}

func TestGetTokenWithPKCS7AttestedDocument_WithoutScope(t *testing.T) {
	mockClient := &MockHttpClient{Response: createSuccessTokenResponse(t)}
	util := NewOAuth2TokenUtil(mockClient)

	resp, err := util.GetTokenWithPKCS7AttestedDocument(
		"https://example.com/oauth/token", "cid", "fed", "doc", "",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response, got nil")
	}
}

func TestGetTokenWithPKCS7AttestedDocument_HttpError(t *testing.T) {
	mockClient := &MockHttpClient{Response: createErrorResponse(http.StatusBadRequest)}
	util := NewOAuth2TokenUtil(mockClient)

	_, err := util.GetTokenWithPKCS7AttestedDocument(
		"https://example.com/oauth/token", "cid", "fed", "doc", "read",
	)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestGetTokenWithOIDCFederatedCredential_Success(t *testing.T) {
	mockClient := &MockHttpClient{Response: createSuccessTokenResponse(t)}
	util := NewOAuth2TokenUtil(mockClient)

	resp, err := util.GetTokenWithOIDCFederatedCredential(
		"https://example.com/oauth/token",
		"client_id",
		"fed_cred",
		"oidc_token",
		"read",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || resp.AccessToken != "test_access_token" {
		t.Errorf("unexpected response: %+v", resp)
	}
}

func TestGetTokenWithOIDCFederatedCredential_WithoutScope(t *testing.T) {
	mockClient := &MockHttpClient{Response: createSuccessTokenResponse(t)}
	util := NewOAuth2TokenUtil(mockClient)

	resp, err := util.GetTokenWithOIDCFederatedCredential(
		"https://example.com/oauth/token", "cid", "fed", "oidc_token", "",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response, got nil")
	}
}

func TestGetTokenWithOIDCFederatedCredential_HttpError(t *testing.T) {
	mockClient := &MockHttpClient{Response: createErrorResponse(http.StatusBadRequest)}
	util := NewOAuth2TokenUtil(mockClient)

	_, err := util.GetTokenWithOIDCFederatedCredential(
		"https://example.com/oauth/token", "cid", "fed", "token", "read",
	)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestRefreshToken_Success(t *testing.T) {
	mockClient := &MockHttpClient{Response: createSuccessTokenResponse(t)}
	util := NewOAuth2TokenUtil(mockClient)

	resp, err := util.RefreshToken(
		"https://example.com/oauth/token",
		"client_id",
		"refresh_token_value",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || resp.AccessToken != "test_access_token" {
		t.Errorf("unexpected response: %+v", resp)
	}
}

func TestRefreshToken_HttpError(t *testing.T) {
	mockClient := &MockHttpClient{Response: createErrorResponse(http.StatusBadRequest)}
	util := NewOAuth2TokenUtil(mockClient)

	_, err := util.RefreshToken(
		"https://example.com/oauth/token", "cid", "refresh_token",
	)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestRefreshToken_NetworkError(t *testing.T) {
	mockClient := &MockHttpClient{Error: stderrors.New("network error")}
	util := NewOAuth2TokenUtil(mockClient)

	_, err := util.RefreshToken(
		"https://example.com/oauth/token", "cid", "refresh_token",
	)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// All WithContext variants share the same logic as their non-ctx counterparts.
// We test success and error scenarios for each.

func TestGetTokenByClientCredentialsWithContext_Success(t *testing.T) {
	mockClient := &MockHttpClient{Response: createSuccessTokenResponse(t)}
	util := NewOAuth2TokenUtil(mockClient)

	resp, err := util.GetTokenByClientCredentialsWithContext(
		context.Background(),
		"https://example.com/oauth/token", "cid", "secret", "read",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || resp.AccessToken != "test_access_token" {
		t.Errorf("unexpected response: %+v", resp)
	}
}

func TestGetTokenByClientCredentialsWithContext_Error(t *testing.T) {
	mockClient := &MockHttpClient{Response: createErrorResponse(http.StatusBadRequest)}
	util := NewOAuth2TokenUtil(mockClient)

	_, err := util.GetTokenByClientCredentialsWithContext(
		context.Background(), "https://example.com/oauth/token", "cid", "secret", "read",
	)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestGetTokenByClientCredentialsBasicWithContext_Success(t *testing.T) {
	var capturedHeaders map[string]string
	mockClient := &headerCapturingClient{
		response: createSuccessTokenResponse(t),
		onCall: func(req *domain.HttpRequest) {
			capturedHeaders = req.Headers
		},
	}
	util := NewOAuth2TokenUtil(mockClient)

	resp, err := util.GetTokenByClientCredentialsBasicWithContext(
		context.Background(),
		"https://example.com/oauth/token", "cid", "secret", "read",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || resp.AccessToken != "test_access_token" {
		t.Errorf("unexpected response: %+v", resp)
	}
	// Verify Basic Auth header is set
	auth := capturedHeaders["Authorization"]
	if auth == "" {
		t.Error("expected Authorization header to be set")
	}
}

func TestGetTokenByClientCredentialsBasicWithContext_Error(t *testing.T) {
	mockClient := &MockHttpClient{Response: createErrorResponse(http.StatusBadRequest)}
	util := NewOAuth2TokenUtil(mockClient)

	_, err := util.GetTokenByClientCredentialsBasicWithContext(
		context.Background(), "https://example.com/oauth/token", "cid", "secret", "read",
	)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestGetTokenByJwtBearerWithContext_Success(t *testing.T) {
	mockClient := &MockHttpClient{Response: createSuccessTokenResponse(t)}
	util := NewOAuth2TokenUtil(mockClient)

	resp, err := util.GetTokenByJwtBearerWithContext(
		context.Background(),
		"https://example.com/oauth/token", "cid", "assertion", "read",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || resp.AccessToken != "test_access_token" {
		t.Errorf("unexpected response: %+v", resp)
	}
}

func TestGetTokenByJwtBearerWithContext_Error(t *testing.T) {
	mockClient := &MockHttpClient{Response: createErrorResponse(http.StatusBadRequest)}
	util := NewOAuth2TokenUtil(mockClient)

	_, err := util.GetTokenByJwtBearerWithContext(
		context.Background(), "https://example.com/oauth/token", "cid", "assertion", "read",
	)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestGetTokenByClientCredentialsJwtAssertionWithContext_Success(t *testing.T) {
	mockClient := &MockHttpClient{Response: createSuccessTokenResponse(t)}
	util := NewOAuth2TokenUtil(mockClient)

	resp, err := util.GetTokenByClientCredentialsJwtAssertionWithContext(
		context.Background(),
		"https://example.com/oauth/token", "cid", "assertion", "read",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || resp.AccessToken != "test_access_token" {
		t.Errorf("unexpected response: %+v", resp)
	}
}

func TestGetTokenByClientCredentialsJwtAssertionWithContext_Error(t *testing.T) {
	mockClient := &MockHttpClient{Response: createErrorResponse(http.StatusBadRequest)}
	util := NewOAuth2TokenUtil(mockClient)

	_, err := util.GetTokenByClientCredentialsJwtAssertionWithContext(
		context.Background(), "https://example.com/oauth/token", "cid", "assertion", "read",
	)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestGetTokenByX509JwtBearerWithContext_Success(t *testing.T) {
	mockClient := &MockHttpClient{Response: createSuccessTokenResponse(t)}
	util := NewOAuth2TokenUtil(mockClient)

	resp, err := util.GetTokenByX509JwtBearerWithContext(
		context.Background(),
		"https://example.com/oauth/token", "cid", "assertion", "cert", "chain", "fed", "read",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || resp.AccessToken != "test_access_token" {
		t.Errorf("unexpected response: %+v", resp)
	}
}

func TestGetTokenByX509JwtBearerWithContext_Error(t *testing.T) {
	mockClient := &MockHttpClient{Response: createErrorResponse(http.StatusBadRequest)}
	util := NewOAuth2TokenUtil(mockClient)

	_, err := util.GetTokenByX509JwtBearerWithContext(
		context.Background(), "https://example.com/oauth/token", "cid", "assertion", "cert", "chain", "fed", "read",
	)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestGetTokenWithPKCS7AttestedDocumentWithContext_Success(t *testing.T) {
	mockClient := &MockHttpClient{Response: createSuccessTokenResponse(t)}
	util := NewOAuth2TokenUtil(mockClient)

	resp, err := util.GetTokenWithPKCS7AttestedDocumentWithContext(
		context.Background(),
		"https://example.com/oauth/token", "cid", "fed", "doc", "read",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || resp.AccessToken != "test_access_token" {
		t.Errorf("unexpected response: %+v", resp)
	}
}

func TestGetTokenWithPKCS7AttestedDocumentWithContext_Error(t *testing.T) {
	mockClient := &MockHttpClient{Response: createErrorResponse(http.StatusBadRequest)}
	util := NewOAuth2TokenUtil(mockClient)

	_, err := util.GetTokenWithPKCS7AttestedDocumentWithContext(
		context.Background(), "https://example.com/oauth/token", "cid", "fed", "doc", "read",
	)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestGetTokenWithOIDCFederatedCredentialWithContext_Success(t *testing.T) {
	mockClient := &MockHttpClient{Response: createSuccessTokenResponse(t)}
	util := NewOAuth2TokenUtil(mockClient)

	resp, err := util.GetTokenWithOIDCFederatedCredentialWithContext(
		context.Background(),
		"https://example.com/oauth/token", "cid", "fed", "oidc_token", "read",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || resp.AccessToken != "test_access_token" {
		t.Errorf("unexpected response: %+v", resp)
	}
}

func TestGetTokenWithOIDCFederatedCredentialWithContext_Error(t *testing.T) {
	mockClient := &MockHttpClient{Response: createErrorResponse(http.StatusBadRequest)}
	util := NewOAuth2TokenUtil(mockClient)

	_, err := util.GetTokenWithOIDCFederatedCredentialWithContext(
		context.Background(), "https://example.com/oauth/token", "cid", "fed", "token", "read",
	)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestGetDeviceCodeWithContext_Success(t *testing.T) {
	mockClient := &MockHttpClient{Response: createSuccessDeviceCodeResponse(t)}
	util := NewOAuth2TokenUtil(mockClient)

	resp, err := util.GetDeviceCodeWithContext(
		context.Background(),
		"https://example.com/device_auth", "cid", "read",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || resp.DeviceCode != "test_device_code" {
		t.Errorf("unexpected response: %+v", resp)
	}
}

func TestGetDeviceCodeWithContext_Error(t *testing.T) {
	mockClient := &MockHttpClient{Response: createErrorResponse(http.StatusBadRequest)}
	util := NewOAuth2TokenUtil(mockClient)

	_, err := util.GetDeviceCodeWithContext(
		context.Background(), "https://example.com/device_auth", "cid", "read",
	)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestGetTokenByDeviceCodeWithContext_Success(t *testing.T) {
	mockClient := &MockHttpClient{Response: createSuccessTokenResponse(t)}
	util := NewOAuth2TokenUtil(mockClient)

	resp, err := util.GetTokenByDeviceCodeWithContext(
		context.Background(),
		"https://example.com/oauth/token", "cid", "device_code",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || resp.AccessToken != "test_access_token" {
		t.Errorf("unexpected response: %+v", resp)
	}
}

func TestGetTokenByDeviceCodeWithContext_Error(t *testing.T) {
	mockClient := &MockHttpClient{Response: createErrorResponse(http.StatusBadRequest)}
	util := NewOAuth2TokenUtil(mockClient)

	_, err := util.GetTokenByDeviceCodeWithContext(
		context.Background(), "https://example.com/oauth/token", "cid", "device_code",
	)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestRefreshTokenWithContext_Success(t *testing.T) {
	mockClient := &MockHttpClient{Response: createSuccessTokenResponse(t)}
	util := NewOAuth2TokenUtil(mockClient)

	resp, err := util.RefreshTokenWithContext(
		context.Background(),
		"https://example.com/oauth/token", "cid", "refresh_token",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || resp.AccessToken != "test_access_token" {
		t.Errorf("unexpected response: %+v", resp)
	}
}

func TestRefreshTokenWithContext_Error(t *testing.T) {
	mockClient := &MockHttpClient{Response: createErrorResponse(http.StatusBadRequest)}
	util := NewOAuth2TokenUtil(mockClient)

	_, err := util.RefreshTokenWithContext(
		context.Background(), "https://example.com/oauth/token", "cid", "refresh_token",
	)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// TestPostFormForTokenWithContext_Success verifies the ctx variant of postFormForToken
func TestPostFormForTokenWithContext_Success(t *testing.T) {
	mockClient := &MockHttpClient{Response: createSuccessDeviceCodeResponse(t)}
	util := NewOAuth2TokenUtil(mockClient)

	var result domain.DeviceCodeResponse
	err := util.postFormForTokenWithContext(
		context.Background(),
		"https://example.com/device_auth", "k=v", &result,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.DeviceCode != "test_device_code" {
		t.Errorf("DeviceCode = %q, want %q", result.DeviceCode, "test_device_code")
	}
}

func TestPostFormForTokenWithContext_Error(t *testing.T) {
	mockClient := &MockHttpClient{Response: createErrorResponse(http.StatusBadRequest)}
	util := NewOAuth2TokenUtil(mockClient)

	var result domain.DeviceCodeResponse
	err := util.postFormForTokenWithContext(
		context.Background(),
		"https://example.com/device_auth", "k=v", &result,
	)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// TestPostFormWithHeadersForTokenResponseWithContext_Success verifies the ctx variant with headers
func TestPostFormWithHeadersForTokenResponseWithContext_Success(t *testing.T) {
	mockClient := &MockHttpClient{Response: createSuccessTokenResponse(t)}
	util := NewOAuth2TokenUtil(mockClient)

	resp, err := util.postFormWithHeadersForTokenResponseWithContext(
		context.Background(),
		"https://example.com/oauth/token", "k=v", map[string]string{"X-Custom": "val"},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || resp.AccessToken != "test_access_token" {
		t.Errorf("unexpected response: %+v", resp)
	}
}

func TestPostFormWithHeadersForTokenResponseWithContext_Error(t *testing.T) {
	mockClient := &MockHttpClient{Response: createErrorResponse(http.StatusBadRequest)}
	util := NewOAuth2TokenUtil(mockClient)

	_, err := util.postFormWithHeadersForTokenResponseWithContext(
		context.Background(),
		"https://example.com/oauth/token", "k=v", nil,
	)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// TestPostFormWithHeadersForTokenResponseWithContext_NetworkError verifies network errors propagate
func TestPostFormWithHeadersForTokenResponseWithContext_NetworkError(t *testing.T) {
	mockClient := &MockHttpClient{Error: stderrors.New("network timeout")}
	util := NewOAuth2TokenUtil(mockClient)

	_, err := util.postFormWithHeadersForTokenResponseWithContext(
		context.Background(),
		"https://example.com/oauth/token", "k=v", nil,
	)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// TestPostFormForTokenWithContext_InvalidJSON verifies JSON parse error propagation
func TestPostFormForTokenWithContext_InvalidJSON(t *testing.T) {
	mockClient := &MockHttpClient{
		Response: &domain.HttpResponse{
			StatusCode: http.StatusOK,
			Headers:    map[string][]string{},
			Body:       []byte("invalid json"),
		},
	}
	util := NewOAuth2TokenUtil(mockClient)

	var result domain.DeviceCodeResponse
	err := util.postFormForTokenWithContext(
		context.Background(),
		"https://example.com/device_auth", "k=v", &result,
	)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
