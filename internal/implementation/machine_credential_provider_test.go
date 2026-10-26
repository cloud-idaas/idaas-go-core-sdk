package implementation

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/cloud-idaas/idaas-go-core-sdk/config"
	"github.com/cloud-idaas/idaas-go-core-sdk/credential"
	"github.com/cloud-idaas/idaas-go-core-sdk/domain"
	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
	"github.com/cloud-idaas/idaas-go-core-sdk/plugin"
	"github.com/cloud-idaas/idaas-go-core-sdk/provider"
)

// mockHttpClientForImpl is a mock HttpClient for the implementation package tests.
type mockHttpClientForImpl struct {
	executeFn   func(req *domain.HttpRequest) (*domain.HttpResponse, error)
	callCount   int
	lastRequest *domain.HttpRequest
}

func (m *mockHttpClientForImpl) Execute(req *domain.HttpRequest) (*domain.HttpResponse, error) {
	m.callCount++
	m.lastRequest = req
	return m.executeFn(req)
}

func (m *mockHttpClientForImpl) ExecuteContext(_ context.Context, req *domain.HttpRequest) (*domain.HttpResponse, error) {
	return m.Execute(req)
}

func (m *mockHttpClientForImpl) Get(url string, headers map[string]string) (*domain.HttpResponse, error) {
	return m.Execute(&domain.HttpRequest{Method: enums.HttpMethodGet, URL: url, Headers: headers})
}

func (m *mockHttpClientForImpl) Post(url string, headers map[string]string, body interface{}) (*domain.HttpResponse, error) {
	return m.Execute(&domain.HttpRequest{Method: enums.HttpMethodPost, URL: url, Headers: headers, Body: body})
}

// makeTokenResponseBody builds a standard OAuth2 token response JSON body using struct fields.
func makeTokenResponseBody(tokenVal string) []byte {
	var resp credential.IDaaSTokenResponse
	resp.AccessToken = tokenVal
	resp.TokenType = "Bearer"
	resp.ExpiresIn = 3600
	resp.Scope = "read"
	b, _ := json.Marshal(&resp)
	return b
}

// generateRSAPrivateKeyPEM generates an RSA private key and returns it as PKCS#8 PEM.
func generateRSAPrivateKeyPEM(t *testing.T) (string, *rsa.PrivateKey) {
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

// generateECDSAPrivateKeyPEM generates an ECDSA private key and returns it as PEM.
func generateECDSAPrivateKeyPEM(t *testing.T) (string, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal EC key: %v", err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	return string(pemData), key
}

const testTokenValue = "testTokenValue"

func TestNewIDaaSMachineCredentialProvider(t *testing.T) {
	cfg := &config.IDaaSClientConfig{
		ClientId:      "test-client-id",
		TokenEndpoint: "https://token.example.com",
		Scope:         "read",
		AuthnConfiguration: &config.IdentityAuthenticationConfiguration{
			AuthnMethod: enums.TokenAuthnMethodClientSecretPost,
		},
	}
	mock := &mockHttpClientForImpl{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 200, Body: makeTokenResponseBody(testTokenValue)}, nil
		},
	}

	prov := NewIDaaSMachineCredentialProvider(cfg, enums.StaleValueBehaviorRefresh, mock)
	if prov == nil {
		t.Fatal("expected non-nil provider")
	}
	if prov.config != cfg {
		t.Errorf("config mismatch")
	}
	if prov.httpClient != mock {
		t.Errorf("httpClient mismatch")
	}
	if prov.AbstractRefreshedCredentialProvider == nil {
		t.Error("expected AbstractRefreshedCredentialProvider to be set")
	}
}

func TestNewIDaaSMachineCredentialProvider_GetCredential(t *testing.T) {
	cfg := &config.IDaaSClientConfig{
		ClientId:      "test-client-id",
		TokenEndpoint: "https://token.example.com",
		Scope:         "read",
		AuthnConfiguration: &config.IdentityAuthenticationConfiguration{
			AuthnMethod:            enums.TokenAuthnMethodClientSecretPost,
			ClientSecretEnvVarName: "TEST_CLIENT_SECRET",
		},
	}
	t.Setenv("TEST_CLIENT_SECRET", "my-secret-value")

	mock := &mockHttpClientForImpl{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 200, Body: makeTokenResponseBody(testTokenValue)}, nil
		},
	}

	prov := NewIDaaSMachineCredentialProvider(cfg, enums.StaleValueBehaviorRefresh, mock)
	cred, err := prov.GetCredential()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred == nil {
		t.Fatal("expected non-nil credential")
	}
	if cred.GetAccessToken() != testTokenValue {
		t.Errorf("expected test token value, got '%s'", cred.GetAccessToken())
	}
}

func TestRefreshCredential_NilAuthnConfiguration(t *testing.T) {
	prov := &IDaaSMachineCredentialProvider{
		config: &config.IDaaSClientConfig{},
	}
	_, err := prov.refreshCredential(context.Background())
	if err == nil {
		t.Fatal("expected error for nil AuthnConfiguration")
	}
}

func TestRefreshCredential_UnsupportedMethod(t *testing.T) {
	prov := &IDaaSMachineCredentialProvider{
		config: &config.IDaaSClientConfig{
			AuthnConfiguration: &config.IdentityAuthenticationConfiguration{
				AuthnMethod: "unsupported_method",
			},
		},
	}
	_, err := prov.refreshCredential(context.Background())
	if err == nil {
		t.Fatal("expected error for unsupported authn method")
	}
}

func TestRefreshCredential_ClientSecretPost(t *testing.T) {
	t.Setenv("TEST_CS_POST", "secret123")
	prov := &IDaaSMachineCredentialProvider{
		config: &config.IDaaSClientConfig{
			ClientId:      "cid",
			TokenEndpoint: "https://token.example.com",
			Scope:         "read",
			AuthnConfiguration: &config.IdentityAuthenticationConfiguration{
				AuthnMethod:            enums.TokenAuthnMethodClientSecretPost,
				ClientSecretEnvVarName: "TEST_CS_POST",
			},
		},
		httpClient: &mockHttpClientForImpl{
			executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
				return &domain.HttpResponse{StatusCode: 200, Body: makeTokenResponseBody(testTokenValue)}, nil
			},
		},
	}
	cred, err := prov.refreshCredential(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred.GetAccessToken() != testTokenValue {
		t.Errorf("unexpected token: %s", cred.GetAccessToken())
	}
}

func TestRefreshCredential_ClientSecretBasic(t *testing.T) {
	t.Setenv("TEST_CS_BASIC", "secret-basic")
	prov := &IDaaSMachineCredentialProvider{
		config: &config.IDaaSClientConfig{
			ClientId:      "cid",
			TokenEndpoint: "https://token.example.com",
			Scope:         "read",
			AuthnConfiguration: &config.IdentityAuthenticationConfiguration{
				AuthnMethod:            enums.TokenAuthnMethodClientSecretBasic,
				ClientSecretEnvVarName: "TEST_CS_BASIC",
			},
		},
		httpClient: &mockHttpClientForImpl{
			executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
				return &domain.HttpResponse{StatusCode: 200, Body: makeTokenResponseBody(testTokenValue)}, nil
			},
		},
	}
	cred, err := prov.refreshCredential(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred.GetAccessToken() != testTokenValue {
		t.Errorf("unexpected token: %s", cred.GetAccessToken())
	}
}

func TestRefreshCredential_ClientSecretJwt(t *testing.T) {
	t.Setenv("TEST_CS_JWT", "jwt-secret")
	prov := &IDaaSMachineCredentialProvider{
		config: &config.IDaaSClientConfig{
			ClientId:      "cid",
			TokenEndpoint: "https://token.example.com",
			Scope:         "read",
			AuthnConfiguration: &config.IdentityAuthenticationConfiguration{
				AuthnMethod:            enums.TokenAuthnMethodClientSecretJwt,
				ClientSecretEnvVarName: "TEST_CS_JWT",
			},
		},
		httpClient: &mockHttpClientForImpl{
			executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
				return &domain.HttpResponse{StatusCode: 200, Body: makeTokenResponseBody(testTokenValue)}, nil
			},
		},
	}
	cred, err := prov.refreshCredential(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred.GetAccessToken() != testTokenValue {
		t.Errorf("unexpected token: %s", cred.GetAccessToken())
	}
}

func TestRefreshCredential_PrivateKeyJwt(t *testing.T) {
	pemStr, _ := generateRSAPrivateKeyPEM(t)
	t.Setenv("TEST_PK_JWT", pemStr)

	prov := &IDaaSMachineCredentialProvider{
		config: &config.IDaaSClientConfig{
			ClientId:       "cid",
			IssuerEndpoint: "https://issuer.example.com",
			TokenEndpoint:  "https://token.example.com",
			Scope:          "read",
			AuthnConfiguration: &config.IdentityAuthenticationConfiguration{
				AuthnMethod:          enums.TokenAuthnMethodPrivateKeyJwt,
				PrivateKeyEnvVarName: "TEST_PK_JWT",
			},
		},
		httpClient: &mockHttpClientForImpl{
			executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
				return &domain.HttpResponse{StatusCode: 200, Body: makeTokenResponseBody(testTokenValue)}, nil
			},
		},
	}
	cred, err := prov.refreshCredential(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred.GetAccessToken() != testTokenValue {
		t.Errorf("unexpected token: %s", cred.GetAccessToken())
	}
}

func TestRefreshCredential_Plugin(t *testing.T) {
	plugin.ResetForTesting()
	defer plugin.ResetForTesting()

	registry := plugin.GetInstance()
	mockProv := &mockPluginProvider{name: "test-plugin"}
	if err := registry.Register(mockProv); err != nil {
		t.Fatalf("failed to register plugin: %v", err)
	}

	prov := &IDaaSMachineCredentialProvider{
		config: &config.IDaaSClientConfig{
			Scope: "read",
			AuthnConfiguration: &config.IdentityAuthenticationConfiguration{
				AuthnMethod: enums.TokenAuthnMethodPlugin,
				PluginName:  "test-plugin",
			},
		},
	}
	cred, err := prov.refreshCredential(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred.GetAccessToken() != "plugin-token" {
		t.Errorf("expected 'plugin-token', got '%s'", cred.GetAccessToken())
	}
}

// mockPluginProvider is a mock implementation of provider.PluginCredentialProvider.
type mockPluginProvider struct {
	name string
}

func (m *mockPluginProvider) GetName() string { return m.name }

func (m *mockPluginProvider) GetIDaaSCredential(scope string) (credential.IDaaSCredential, error) {
	return &mockTestCredential{accessToken: "plugin-token"}, nil
}

func TestLoadPrivateKeyFromEnv_NoEnvVarName(t *testing.T) {
	prov := &IDaaSMachineCredentialProvider{
		config: &config.IDaaSClientConfig{
			AuthnConfiguration: &config.IdentityAuthenticationConfiguration{},
		},
	}
	_, err := prov.loadPrivateKeyFromEnv("pca")
	if err == nil {
		t.Fatal("expected error for empty PrivateKeyEnvVarName")
	}
}

func TestLoadPrivateKeyFromEnv_EmptyEnvValue(t *testing.T) {
	t.Setenv("TEST_EMPTY_KEY", "")
	prov := &IDaaSMachineCredentialProvider{
		config: &config.IDaaSClientConfig{
			AuthnConfiguration: &config.IdentityAuthenticationConfiguration{
				PrivateKeyEnvVarName: "TEST_EMPTY_KEY",
			},
		},
	}
	_, err := prov.loadPrivateKeyFromEnv("pca")
	if err == nil {
		t.Fatal("expected error for empty env value")
	}
}

func TestLoadPrivateKeyFromEnv_InvalidPEM(t *testing.T) {
	t.Setenv("TEST_INVALID_PEM", "not-a-valid-pem")
	prov := &IDaaSMachineCredentialProvider{
		config: &config.IDaaSClientConfig{
			AuthnConfiguration: &config.IdentityAuthenticationConfiguration{
				PrivateKeyEnvVarName: "TEST_INVALID_PEM",
			},
		},
	}
	_, err := prov.loadPrivateKeyFromEnv("pca")
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestLoadPrivateKeyFromEnv_ValidRSAKey(t *testing.T) {
	pemStr, _ := generateRSAPrivateKeyPEM(t)
	t.Setenv("TEST_VALID_RSA", pemStr)
	prov := &IDaaSMachineCredentialProvider{
		config: &config.IDaaSClientConfig{
			AuthnConfiguration: &config.IdentityAuthenticationConfiguration{
				PrivateKeyEnvVarName: "TEST_VALID_RSA",
			},
		},
	}
	key, err := prov.loadPrivateKeyFromEnv("pca")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}
}

func TestGetClientSecretCredential_EmptySecret(t *testing.T) {
	t.Setenv("TEST_EMPTY_CS", "")
	prov := &IDaaSMachineCredentialProvider{
		config: &config.IDaaSClientConfig{
			AuthnConfiguration: &config.IdentityAuthenticationConfiguration{
				ClientSecretEnvVarName: "TEST_EMPTY_CS",
			},
		},
	}
	_, err := prov.getClientSecretCredential(context.Background())
	if err == nil {
		t.Fatal("expected error for empty client secret")
	}
}

func TestGetClientSecretCredential_Success(t *testing.T) {
	t.Setenv("TEST_VALID_CS", "my-secret-value")
	mock := &mockHttpClientForImpl{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 200, Body: makeTokenResponseBody(testTokenValue)}, nil
		},
	}
	prov := &IDaaSMachineCredentialProvider{
		config: &config.IDaaSClientConfig{
			ClientId:      "cid",
			TokenEndpoint: "https://token.example.com",
			Scope:         "read",
			AuthnConfiguration: &config.IdentityAuthenticationConfiguration{
				ClientSecretEnvVarName: "TEST_VALID_CS",
				AuthnMethod:            enums.TokenAuthnMethodClientSecretPost,
			},
		},
		httpClient: mock,
	}
	cred, err := prov.getClientSecretCredential(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred.GetAccessToken() != testTokenValue {
		t.Errorf("unexpected token: %s", cred.GetAccessToken())
	}
}

func TestGetPrivateKeyJwtCredential_Success(t *testing.T) {
	pemStr, _ := generateRSAPrivateKeyPEM(t)
	t.Setenv("TEST_PK_VALID", pemStr)
	mock := &mockHttpClientForImpl{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 200, Body: makeTokenResponseBody(testTokenValue)}, nil
		},
	}
	prov := &IDaaSMachineCredentialProvider{
		config: &config.IDaaSClientConfig{
			ClientId:       "cid",
			IssuerEndpoint: "https://issuer.example.com",
			TokenEndpoint:  "https://token.example.com",
			Scope:          "read",
			AuthnConfiguration: &config.IdentityAuthenticationConfiguration{
				PrivateKeyEnvVarName: "TEST_PK_VALID",
			},
		},
		httpClient: mock,
	}
	cred, err := prov.getPrivateKeyJwtCredential(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred.GetAccessToken() != testTokenValue {
		t.Errorf("unexpected token: %s", cred.GetAccessToken())
	}
}

func TestGetPcaCredential_Success(t *testing.T) {
	pemStr, _ := generateRSAPrivateKeyPEM(t)
	t.Setenv("TEST_PCA_KEY", pemStr)
	mock := &mockHttpClientForImpl{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 200, Body: makeTokenResponseBody(testTokenValue)}, nil
		},
	}
	prov := &IDaaSMachineCredentialProvider{
		config: &config.IDaaSClientConfig{
			ClientId:      "cid",
			TokenEndpoint: "https://token.example.com",
			Scope:         "read",
			AuthnConfiguration: &config.IdentityAuthenticationConfiguration{
				PrivateKeyEnvVarName:               "TEST_PCA_KEY",
				ClientX509Certificate:              "fake-cert",
				X509CertChains:                     "fake-chain",
				ApplicationFederatedCredentialName: "fake-fc-name",
			},
		},
		httpClient: mock,
	}
	cred, err := prov.getPcaCredential(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred.GetAccessToken() != testTokenValue {
		t.Errorf("unexpected token: %s", cred.GetAccessToken())
	}
}

func TestGetPcaCredential_ECDSAKey(t *testing.T) {
	pemStr, _ := generateECDSAPrivateKeyPEM(t)
	t.Setenv("TEST_PCA_ECDSA", pemStr)
	mock := &mockHttpClientForImpl{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 200, Body: makeTokenResponseBody(testTokenValue)}, nil
		},
	}
	prov := &IDaaSMachineCredentialProvider{
		config: &config.IDaaSClientConfig{
			ClientId:      "cid",
			TokenEndpoint: "https://token.example.com",
			Scope:         "read",
			AuthnConfiguration: &config.IdentityAuthenticationConfiguration{
				PrivateKeyEnvVarName:               "TEST_PCA_ECDSA",
				ClientX509Certificate:              "fake-cert",
				X509CertChains:                     "fake-chain",
				ApplicationFederatedCredentialName: "fake-fc-name",
			},
		},
		httpClient: mock,
	}
	cred, err := prov.getPcaCredential(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred.GetAccessToken() != testTokenValue {
		t.Errorf("unexpected token: %s", cred.GetAccessToken())
	}
}

func TestGetPkcs7Credential_EmptyFederatedName(t *testing.T) {
	prov := &IDaaSMachineCredentialProvider{
		config: &config.IDaaSClientConfig{
			AuthnConfiguration: &config.IdentityAuthenticationConfiguration{
				ClientDeployEnvironment: enums.ClientDeployEnvironmentAlibabaCloudEcs,
			},
		},
	}
	_, err := prov.getPkcs7Credential(context.Background())
	if err == nil {
		t.Fatal("expected error for empty applicationFederatedCredentialName")
	}
}

func TestGetPkcs7CredentialForDeployEnv_Unsupported(t *testing.T) {
	prov := &IDaaSMachineCredentialProvider{
		config: &config.IDaaSClientConfig{
			AuthnConfiguration: &config.IdentityAuthenticationConfiguration{
				ApplicationFederatedCredentialName: "fake-fc-name",
				ClientDeployEnvironment:            "UNSUPPORTED_ENV",
			},
		},
	}
	_, err := prov.getPkcs7CredentialForDeployEnv(context.Background(), "UNSUPPORTED_ENV")
	if err == nil {
		t.Fatal("expected error for unsupported deploy environment")
	}
}

func TestGetPkcs7CredentialForDeployEnv_AlibabaCloudEcs(t *testing.T) {
	mock := &mockHttpClientForImpl{}
	mock.executeFn = func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
		if req.Method == enums.HttpMethodPut {
			return &domain.HttpResponse{StatusCode: 200, Body: []byte("ecs-metadata-token")}, nil
		}
		if req.Method == enums.HttpMethodGet {
			return &domain.HttpResponse{StatusCode: 200, Body: []byte("pkcs7-signed-doc")}, nil
		}
		return &domain.HttpResponse{StatusCode: 200, Body: makeTokenResponseBody(testTokenValue)}, nil
	}

	prov := &IDaaSMachineCredentialProvider{
		config: &config.IDaaSClientConfig{
			ClientId:      "cid",
			TokenEndpoint: "https://token.example.com",
			Scope:         "read",
			InstanceId:    "inst-123",
			AuthnConfiguration: &config.IdentityAuthenticationConfiguration{
				ApplicationFederatedCredentialName: "fake-fc-name",
			},
		},
		httpClient: mock,
	}

	cred, err := prov.getPkcs7CredentialForDeployEnv(context.Background(), enums.ClientDeployEnvironmentAlibabaCloudEcs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred.GetAccessToken() != testTokenValue {
		t.Errorf("unexpected token: %s", cred.GetAccessToken())
	}
}

func TestGetPkcs7CredentialForDeployEnv_AwsEc2(t *testing.T) {
	mock := &mockHttpClientForImpl{}
	mock.executeFn = func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
		if req.Method == enums.HttpMethodPut {
			return &domain.HttpResponse{StatusCode: 200, Body: []byte("aws-metadata-token")}, nil
		}
		if req.Method == enums.HttpMethodGet {
			return &domain.HttpResponse{StatusCode: 200, Body: []byte("aws-pkcs7-doc")}, nil
		}
		return &domain.HttpResponse{StatusCode: 200, Body: makeTokenResponseBody(testTokenValue)}, nil
	}

	prov := &IDaaSMachineCredentialProvider{
		config: &config.IDaaSClientConfig{
			ClientId:      "cid",
			TokenEndpoint: "https://token.example.com",
			Scope:         "read",
			AuthnConfiguration: &config.IdentityAuthenticationConfiguration{
				ApplicationFederatedCredentialName: "fake-fc-name",
			},
		},
		httpClient: mock,
	}

	cred, err := prov.getPkcs7CredentialForDeployEnv(context.Background(), enums.ClientDeployEnvironmentAwsEc2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred.GetAccessToken() != testTokenValue {
		t.Errorf("unexpected token: %s", cred.GetAccessToken())
	}
}

func TestGetOidcCredentialForDeployEnv_Unsupported(t *testing.T) {
	prov := &IDaaSMachineCredentialProvider{
		config: &config.IDaaSClientConfig{
			AuthnConfiguration: &config.IdentityAuthenticationConfiguration{
				ApplicationFederatedCredentialName: "fake-fc-name",
			},
		},
	}
	_, err := prov.getOidcCredentialForDeployEnv(context.Background(), "UNSUPPORTED")
	if err == nil {
		t.Fatal("expected error for unsupported deploy environment")
	}
}

func TestGetOidcCredentialForDeployEnv_ComputerNoTokenPath(t *testing.T) {
	prov := &IDaaSMachineCredentialProvider{
		config: &config.IDaaSClientConfig{
			AuthnConfiguration: &config.IdentityAuthenticationConfiguration{
				ApplicationFederatedCredentialName: "fake-fc-name",
				ClientDeployEnvironment:            enums.ClientDeployEnvironmentComputer,
			},
		},
	}
	_, err := prov.getOidcCredentialForDeployEnv(context.Background(), enums.ClientDeployEnvironmentComputer)
	if err == nil {
		t.Fatal("expected error for COMPUTER without token path")
	}
}

// KUBERNETES deploy env with OidcTokenFilePathEnvVarName configured but env var
// unset/empty → must return a config error, NOT silently fall back to default SA token path.
func TestGetOidcCredentialForDeployEnv_K8sEnvVarConfiguredButEmpty(t *testing.T) {
	// Set env var to empty to simulate "configured but not set"
	t.Setenv("IDAAS_TEST_OIDC_TOKEN_PATH", "")
	prov := &IDaaSMachineCredentialProvider{
		config: &config.IDaaSClientConfig{
			AuthnConfiguration: &config.IdentityAuthenticationConfiguration{
				ApplicationFederatedCredentialName: "fake-fc-name",
				ClientDeployEnvironment:            enums.ClientDeployEnvironmentKubernetes,
				OidcTokenFilePathEnvVarName:        "IDAAS_TEST_OIDC_TOKEN_PATH",
			},
		},
	}
	_, err := prov.getOidcCredentialForDeployEnv(context.Background(), enums.ClientDeployEnvironmentKubernetes)
	if err == nil {
		t.Fatal("expected config error for KUBERNETES with configured env var resolving to empty")
	}
	if !strings.Contains(err.Error(), "oidcTokenFilePathEnvVarName") {
		t.Errorf("expected error mentioning oidcTokenFilePathEnvVarName, got: %v", err)
	}
}

func TestGetOidcCredentialForDeployEnv_GoogleVmNoIssuer(t *testing.T) {
	prov := &IDaaSMachineCredentialProvider{
		config: &config.IDaaSClientConfig{
			AuthnConfiguration: &config.IdentityAuthenticationConfiguration{
				ApplicationFederatedCredentialName: "fake-fc-name",
			},
		},
	}
	_, err := prov.getOidcCredentialForDeployEnv(context.Background(), enums.ClientDeployEnvironmentGoogleVm)
	if err == nil {
		t.Fatal("expected error for GOOGLE_VM without issuer")
	}
}

func TestGetOidcCredentialForDeployEnv_GoogleVmInvalidIssuer(t *testing.T) {
	prov := &IDaaSMachineCredentialProvider{
		config: &config.IDaaSClientConfig{
			IssuerEndpoint: "://invalid-url",
			AuthnConfiguration: &config.IdentityAuthenticationConfiguration{
				ApplicationFederatedCredentialName: "fake-fc-name",
			},
		},
	}
	_, err := prov.getOidcCredentialForDeployEnv(context.Background(), enums.ClientDeployEnvironmentGoogleVm)
	if err == nil {
		t.Fatal("expected error for invalid issuer URL")
	}
}

func TestGetPluginCredential_EmptyPluginName(t *testing.T) {
	prov := &IDaaSMachineCredentialProvider{
		config: &config.IDaaSClientConfig{
			AuthnConfiguration: &config.IdentityAuthenticationConfiguration{},
		},
	}
	_, err := prov.getPluginCredential(context.Background())
	if err == nil {
		t.Fatal("expected error for empty plugin name")
	}
}

func TestGetPluginCredential_NotFound(t *testing.T) {
	plugin.ResetForTesting()
	defer plugin.ResetForTesting()

	prov := &IDaaSMachineCredentialProvider{
		config: &config.IDaaSClientConfig{
			AuthnConfiguration: &config.IdentityAuthenticationConfiguration{
				PluginName: "non-existent-plugin",
			},
		},
	}
	_, err := prov.getPluginCredential(context.Background())
	if err == nil {
		t.Fatal("expected error for non-existent plugin")
	}
}

func TestGetPluginCredential_Success(t *testing.T) {
	plugin.ResetForTesting()
	defer plugin.ResetForTesting()

	registry := plugin.GetInstance()
	mockProv := &mockPluginProvider{name: "test-plugin-cred"}
	if err := registry.Register(mockProv); err != nil {
		t.Fatalf("failed to register plugin: %v", err)
	}

	prov := &IDaaSMachineCredentialProvider{
		config: &config.IDaaSClientConfig{
			Scope: "read",
			AuthnConfiguration: &config.IdentityAuthenticationConfiguration{
				PluginName: "test-plugin-cred",
			},
		},
	}
	cred, err := prov.getPluginCredential(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred.GetAccessToken() != "plugin-token" {
		t.Errorf("expected 'plugin-token', got '%s'", cred.GetAccessToken())
	}
}

// Ensure mockPluginProvider satisfies provider.PluginCredentialProvider
var _ provider.PluginCredentialProvider = (*mockPluginProvider)(nil)
