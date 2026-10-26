package authentication

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"

	"github.com/cloud-idaas/idaas-go-core-sdk/credential"
	"github.com/cloud-idaas/idaas-go-core-sdk/domain"
	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
)

// mockAuthHttpClient is a mock HttpClient for authentication package tests.
type mockAuthHttpClient struct {
	executeFn func(req *domain.HttpRequest) (*domain.HttpResponse, error)
}

func (m *mockAuthHttpClient) Execute(req *domain.HttpRequest) (*domain.HttpResponse, error) {
	return m.executeFn(req)
}

func (m *mockAuthHttpClient) ExecuteContext(_ context.Context, req *domain.HttpRequest) (*domain.HttpResponse, error) {
	return m.Execute(req)
}

func (m *mockAuthHttpClient) Get(url string, headers map[string]string) (*domain.HttpResponse, error) {
	return m.Execute(&domain.HttpRequest{Method: enums.HttpMethodGet, URL: url, Headers: headers})
}

func (m *mockAuthHttpClient) Post(url string, headers map[string]string, body interface{}) (*domain.HttpResponse, error) {
	return m.Execute(&domain.HttpRequest{Method: enums.HttpMethodPost, URL: url, Headers: headers, Body: body})
}

// makeAuthTokenResponseBody builds a token response JSON body using struct fields.
func makeAuthTokenResponseBody(tokenVal string) []byte {
	var resp credential.IDaaSTokenResponse
	resp.AccessToken = tokenVal
	resp.TokenType = "Bearer"
	resp.ExpiresIn = 3600
	resp.Scope = "read"
	b, _ := json.Marshal(&resp)
	return b
}

const authTestTokenValue = "authTestTokenValue"

func generateAuthRSAPrivateKeyPEM(t *testing.T) (string, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal PKCS8: %v", err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return string(pemData), key
}

func generateAuthECDSAPrivateKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}
	return key
}

// --- StaticClientSecretAssertionProvider tests ---

func TestNewStaticClientSecretAssertionProvider(t *testing.T) {
	mock := &mockAuthHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 200, Body: makeAuthTokenResponseBody(authTestTokenValue)}, nil
		},
	}
	p := NewStaticClientSecretAssertionProvider("cid", "secret", "https://token.example.com", "read", enums.TokenAuthnMethodClientSecretPost, mock)
	if p == nil {
		t.Fatal("expected non-nil provider")
	}
	if p.clientId != "cid" {
		t.Errorf("expected clientId 'cid', got '%s'", p.clientId)
	}
	if p.clientSecret != "secret" {
		t.Errorf("expected clientSecret 'secret', got '%s'", p.clientSecret)
	}
	if p.tokenEndpoint != "https://token.example.com" {
		t.Errorf("unexpected tokenEndpoint")
	}
	if p.scope != "read" {
		t.Errorf("unexpected scope")
	}
	if p.authnMethod != enums.TokenAuthnMethodClientSecretPost {
		t.Errorf("unexpected authnMethod")
	}
	if p.tokenUtil == nil {
		t.Error("expected non-nil tokenUtil")
	}
}

func TestStaticClientSecretProvider_GetCredential_Post(t *testing.T) {
	mock := &mockAuthHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 200, Body: makeAuthTokenResponseBody(authTestTokenValue)}, nil
		},
	}
	p := NewStaticClientSecretAssertionProvider("cid", "secret", "https://token.example.com", "read", enums.TokenAuthnMethodClientSecretPost, mock)
	cred, err := p.GetCredential()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred.GetAccessToken() != authTestTokenValue {
		t.Errorf("unexpected token: %s", cred.GetAccessToken())
	}
}

func TestStaticClientSecretProvider_GetCredential_Basic(t *testing.T) {
	mock := &mockAuthHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 200, Body: makeAuthTokenResponseBody(authTestTokenValue)}, nil
		},
	}
	p := NewStaticClientSecretAssertionProvider("cid", "secret", "https://token.example.com", "read", enums.TokenAuthnMethodClientSecretBasic, mock)
	cred, err := p.GetCredential()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred.GetAccessToken() != authTestTokenValue {
		t.Errorf("unexpected token: %s", cred.GetAccessToken())
	}
}

func TestStaticClientSecretProvider_GetCredential_Jwt(t *testing.T) {
	mock := &mockAuthHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 200, Body: makeAuthTokenResponseBody(authTestTokenValue)}, nil
		},
	}
	p := NewStaticClientSecretAssertionProvider("cid", "my-jwt-secret", "https://token.example.com", "read", enums.TokenAuthnMethodClientSecretJwt, mock)
	cred, err := p.GetCredential()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred.GetAccessToken() != authTestTokenValue {
		t.Errorf("unexpected token: %s", cred.GetAccessToken())
	}
}

func TestStaticClientSecretProvider_GetCredentialWithContext(t *testing.T) {
	mock := &mockAuthHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 200, Body: makeAuthTokenResponseBody(authTestTokenValue)}, nil
		},
	}
	p := NewStaticClientSecretAssertionProvider("cid", "secret", "https://token.example.com", "read", enums.TokenAuthnMethodClientSecretPost, mock)
	cred, err := p.GetCredentialWithContext(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred.GetAccessToken() != authTestTokenValue {
		t.Errorf("unexpected token: %s", cred.GetAccessToken())
	}
}

func TestStaticClientSecretProvider_CreateHs256Assertion_EmptySecret(t *testing.T) {
	p := &StaticClientSecretAssertionProvider{
		clientSecret: "",
	}
	_, err := p.createHs256Assertion()
	if err == nil {
		t.Fatal("expected error for empty client secret")
	}
}

func TestStaticClientSecretProvider_CreateHs256Assertion_Success(t *testing.T) {
	p := &StaticClientSecretAssertionProvider{
		clientId:      "cid",
		clientSecret:  "test-secret",
		tokenEndpoint: "https://token.example.com",
	}
	assertion, err := p.createHs256Assertion()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if assertion == "" {
		t.Fatal("expected non-empty assertion")
	}
	// JWT should have 3 parts
	parts := splitJwt(assertion)
	if len(parts) != 3 {
		t.Fatalf("expected 3-part JWT, got %d parts", len(parts))
	}
}

func splitJwt(s string) []string {
	var parts []string
	start := 0
	for i, c := range s {
		if c == '.' {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}

// --- StaticPrivateKeyAssertionProvider tests ---

func TestNewStaticPrivateKeyAssertionProvider(t *testing.T) {
	mock := &mockAuthHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 200, Body: makeAuthTokenResponseBody(authTestTokenValue)}, nil
		},
	}
	_, rsaKey := generateAuthRSAPrivateKeyPEM(t)
	// issuer 参数已移除(IDaaS private_key_jwt 规范要求 iss=clientId,
	// issuer URL 不参与 assertion 构造)。
	p := NewStaticPrivateKeyAssertionProvider("cid", rsaKey, "https://token.example.com", "read", mock)
	if p == nil {
		t.Fatal("expected non-nil provider")
	}
	if p.clientId != "cid" {
		t.Errorf("expected clientId 'cid'")
	}
	if p.tokenEndpoint != "https://token.example.com" {
		t.Errorf("unexpected tokenEndpoint")
	}
	if p.scope != "read" {
		t.Errorf("unexpected scope")
	}
	if p.tokenUtil == nil {
		t.Error("expected non-nil tokenUtil")
	}
}

func TestStaticPrivateKeyProvider_GetCredential_RSA(t *testing.T) {
	mock := &mockAuthHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 200, Body: makeAuthTokenResponseBody(authTestTokenValue)}, nil
		},
	}
	_, rsaKey := generateAuthRSAPrivateKeyPEM(t)
	p := NewStaticPrivateKeyAssertionProvider("cid", rsaKey, "https://token.example.com", "read", mock)
	cred, err := p.GetCredential()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred.GetAccessToken() != authTestTokenValue {
		t.Errorf("unexpected token: %s", cred.GetAccessToken())
	}
}

func TestStaticPrivateKeyProvider_GetCredential_ECDSA(t *testing.T) {
	mock := &mockAuthHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 200, Body: makeAuthTokenResponseBody(authTestTokenValue)}, nil
		},
	}
	ecKey := generateAuthECDSAPrivateKey(t)
	p := NewStaticPrivateKeyAssertionProvider("cid", ecKey, "https://token.example.com", "read", mock)
	cred, err := p.GetCredential()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred.GetAccessToken() != authTestTokenValue {
		t.Errorf("unexpected token: %s", cred.GetAccessToken())
	}
}

func TestStaticPrivateKeyProvider_GetCredentialWithContext(t *testing.T) {
	mock := &mockAuthHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 200, Body: makeAuthTokenResponseBody(authTestTokenValue)}, nil
		},
	}
	_, rsaKey := generateAuthRSAPrivateKeyPEM(t)
	p := NewStaticPrivateKeyAssertionProvider("cid", rsaKey, "https://token.example.com", "read", mock)
	cred, err := p.GetCredentialWithContext(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred.GetAccessToken() != authTestTokenValue {
		t.Errorf("unexpected token: %s", cred.GetAccessToken())
	}
}

func TestStaticPrivateKeyProvider_CreateAssertion_UnsupportedKey(t *testing.T) {
	p := &StaticPrivateKeyAssertionProvider{
		privateKey: "not-a-key",
	}
	_, err := p.createAssertion()
	if err == nil {
		t.Fatal("expected error for unsupported key type")
	}
}

// --- StaticX509AssertionProvider tests ---

func TestNewStaticX509AssertionProvider(t *testing.T) {
	mock := &mockAuthHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 200, Body: makeAuthTokenResponseBody(authTestTokenValue)}, nil
		},
	}
	_, rsaKey := generateAuthRSAPrivateKeyPEM(t)
	p := NewStaticX509AssertionProvider("cid", rsaKey, "cert", "chain", "fc-name", "https://token.example.com", "read", mock)
	if p == nil {
		t.Fatal("expected non-nil provider")
	}
	if p.clientId != "cid" {
		t.Errorf("expected clientId 'cid'")
	}
	if p.clientX509 != "cert" {
		t.Errorf("unexpected clientX509")
	}
	if p.clientX509Chain != "chain" {
		t.Errorf("unexpected clientX509Chain")
	}
	if p.federatedCredentialName != "fc-name" {
		t.Errorf("unexpected federatedCredentialName")
	}
	if p.tokenUtil == nil {
		t.Error("expected non-nil tokenUtil")
	}
}

func TestStaticX509Provider_GetCredential_Success(t *testing.T) {
	mock := &mockAuthHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 200, Body: makeAuthTokenResponseBody(authTestTokenValue)}, nil
		},
	}
	_, rsaKey := generateAuthRSAPrivateKeyPEM(t)
	p := NewStaticX509AssertionProvider("cid", rsaKey, "cert-pem", "chain-pem", "fc-name", "https://token.example.com", "read", mock)
	cred, err := p.GetCredential()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred.GetAccessToken() != authTestTokenValue {
		t.Errorf("unexpected token: %s", cred.GetAccessToken())
	}
}

func TestStaticX509Provider_GetCredential_ECDSA(t *testing.T) {
	mock := &mockAuthHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 200, Body: makeAuthTokenResponseBody(authTestTokenValue)}, nil
		},
	}
	ecKey := generateAuthECDSAPrivateKey(t)
	p := NewStaticX509AssertionProvider("cid", ecKey, "cert-pem", "chain-pem", "fc-name", "https://token.example.com", "read", mock)
	cred, err := p.GetCredential()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred.GetAccessToken() != authTestTokenValue {
		t.Errorf("unexpected token: %s", cred.GetAccessToken())
	}
}

func TestStaticX509Provider_GetCredential_EmptyX509(t *testing.T) {
	mock := &mockAuthHttpClient{}
	_, rsaKey := generateAuthRSAPrivateKeyPEM(t)
	p := NewStaticX509AssertionProvider("cid", rsaKey, "", "chain", "fc-name", "https://token.example.com", "read", mock)
	_, err := p.GetCredential()
	if err == nil {
		t.Fatal("expected error for empty clientX509")
	}
}

func TestStaticX509Provider_GetCredentialWithContext_Success(t *testing.T) {
	mock := &mockAuthHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 200, Body: makeAuthTokenResponseBody(authTestTokenValue)}, nil
		},
	}
	_, rsaKey := generateAuthRSAPrivateKeyPEM(t)
	p := NewStaticX509AssertionProvider("cid", rsaKey, "cert-pem", "chain-pem", "fc-name", "https://token.example.com", "read", mock)
	cred, err := p.GetCredentialWithContext(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred.GetAccessToken() != authTestTokenValue {
		t.Errorf("unexpected token: %s", cred.GetAccessToken())
	}
}

func TestStaticX509Provider_CreateAssertion_UnsupportedKey(t *testing.T) {
	p := &StaticX509AssertionProvider{
		privateKey: 12345,
	}
	_, err := p.createAssertion()
	if err == nil {
		t.Fatal("expected error for unsupported key type")
	}
}
