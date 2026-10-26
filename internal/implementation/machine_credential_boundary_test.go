package implementation

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloud-idaas/idaas-go-core-sdk/config"
	"github.com/cloud-idaas/idaas-go-core-sdk/constants"
	"github.com/cloud-idaas/idaas-go-core-sdk/domain"
	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
	"github.com/cloud-idaas/idaas-go-core-sdk/errors"
)

// TestBoundary_GetOidcKubernetes_EnvVarPath verifies that when
// OidcTokenFilePath is empty but OidcTokenFilePathEnvVarName is set,
// the token path is read from the environment variable.
func TestBoundary_GetOidcKubernetes_EnvVarPath(t *testing.T) {
	tmpDir := t.TempDir()
	tokenFile := filepath.Join(tmpDir, "my-token")
	if err := os.WriteFile(tokenFile, []byte("fake-jwt-token"), 0o600); err != nil {
		t.Fatalf("failed to write token file: %v", err)
	}
	t.Setenv("MY_TOKEN_PATH", tokenFile)

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
				ApplicationFederatedCredentialName: "fc-name",
				ClientDeployEnvironment:            enums.ClientDeployEnvironmentKubernetes,
				OidcTokenFilePath:                  "",
				OidcTokenFilePathEnvVarName:        "MY_TOKEN_PATH",
			},
		},
		httpClient: mock,
	}

	cred, err := prov.getOidcCredentialForDeployEnv(context.Background(), enums.ClientDeployEnvironmentKubernetes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred == nil {
		t.Fatal("expected non-nil credential")
	}
	if cred.GetAccessToken() != testTokenValue {
		t.Errorf("expected token %q, got %q", testTokenValue, cred.GetAccessToken())
	}
}

// TestBoundary_GetOidcKubernetes_DefaultPath verifies that when both
// OidcTokenFilePath and OidcTokenFilePathEnvVarName are empty,
// the provider falls back to the default K8s service account token path.
func TestBoundary_GetOidcKubernetes_DefaultPath(t *testing.T) {
	// The default K8s token path may or may not exist in the test environment.
	// If it exists (e.g., running inside a K8s pod), the flow proceeds to the
	// OAuth2 token exchange; if not, the file read fails first.
	// Either way, the default path must appear in the flow — proving the fallback.

	if _, statErr := os.Stat(constants.K8sServiceAccountTokenPath); statErr != nil {
		// K8s token file does not exist — the error should mention the default path.
		prov := &IDaaSMachineCredentialProvider{
			config: &config.IDaaSClientConfig{
				AuthnConfiguration: &config.IdentityAuthenticationConfiguration{
					ApplicationFederatedCredentialName: "fc-name",
					ClientDeployEnvironment:            enums.ClientDeployEnvironmentKubernetes,
				},
			},
			httpClient: &mockHttpClientForImpl{},
		}
		_, err := prov.getOidcCredentialForDeployEnv(context.Background(), enums.ClientDeployEnvironmentKubernetes)
		if err == nil {
			t.Fatal("expected error for default K8s path (file does not exist)")
		}
		if !strings.Contains(err.Error(), constants.K8sServiceAccountTokenPath) {
			t.Errorf("expected error to mention default K8s path %q, got: %v",
				constants.K8sServiceAccountTokenPath, err)
		}
		return
	}

	// K8s token file exists — the flow should proceed to the OAuth2 token exchange.
	// Provide a mock that returns a token response, proving the default path was read.
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
				ApplicationFederatedCredentialName: "fc-name",
				ClientDeployEnvironment:            enums.ClientDeployEnvironmentKubernetes,
			},
		},
		httpClient: mock,
	}
	cred, err := prov.getOidcCredentialForDeployEnv(context.Background(), enums.ClientDeployEnvironmentKubernetes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred == nil {
		t.Fatal("expected non-nil credential (default K8s path was read)")
	}
	if cred.GetAccessToken() != testTokenValue {
		t.Errorf("expected token %q, got %q", testTokenValue, cred.GetAccessToken())
	}
}

// TestBoundary_GetOidcKubernetes_ExplicitPath verifies that when
// OidcTokenFilePath is set explicitly, it is used directly.
func TestBoundary_GetOidcKubernetes_ExplicitPath(t *testing.T) {
	tmpDir := t.TempDir()
	tokenFile := filepath.Join(tmpDir, "explicit-token")
	if err := os.WriteFile(tokenFile, []byte("fake-jwt-token"), 0o600); err != nil {
		t.Fatalf("failed to write token file: %v", err)
	}

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
				ApplicationFederatedCredentialName: "fc-name",
				ClientDeployEnvironment:            enums.ClientDeployEnvironmentKubernetes,
				OidcTokenFilePath:                  tokenFile,
			},
		},
		httpClient: mock,
	}

	cred, err := prov.getOidcCredentialForDeployEnv(context.Background(), enums.ClientDeployEnvironmentKubernetes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred == nil {
		t.Fatal("expected non-nil credential")
	}
	if cred.GetAccessToken() != testTokenValue {
		t.Errorf("expected token %q, got %q", testTokenValue, cred.GetAccessToken())
	}
}

// TestBoundary_RefreshCredential_DispatchPCA verifies that AuthnMethod=PCA
// dispatches to getPcaCredential. With no PrivateKeyEnvVarName, loadPrivateKeyFromEnv
// returns a ConfigError with code PrivateKeyEnvVarNameNotFound — confirming the dispatch.
func TestBoundary_RefreshCredential_DispatchPCA(t *testing.T) {
	prov := &IDaaSMachineCredentialProvider{
		config: &config.IDaaSClientConfig{
			AuthnConfiguration: &config.IdentityAuthenticationConfiguration{
				AuthnMethod: enums.TokenAuthnMethodPca,
				// PrivateKeyEnvVarName intentionally empty
			},
		},
	}

	_, err := prov.refreshCredential(context.Background())
	if err == nil {
		t.Fatal("expected error for PCA without PrivateKeyEnvVarName")
	}
	if !errors.HasCode(err, constants.PrivateKeyEnvVarNameNotFound) {
		t.Errorf("expected error code %q (dispatched to getPcaCredential→loadPrivateKeyFromEnv), got: %v",
			constants.PrivateKeyEnvVarNameNotFound, err)
	}
}

// TestBoundary_RefreshCredential_DispatchPkcs7 verifies that AuthnMethod=Pkcs7
// dispatches to getPkcs7Credential. With no ApplicationFederatedCredentialName,
// getPkcs7CredentialForDeployEnv returns a ConfigError with code
// ApplicationFederatedCredentialNameNotFound — confirming the dispatch.
func TestBoundary_RefreshCredential_DispatchPkcs7(t *testing.T) {
	prov := &IDaaSMachineCredentialProvider{
		config: &config.IDaaSClientConfig{
			AuthnConfiguration: &config.IdentityAuthenticationConfiguration{
				AuthnMethod:             enums.TokenAuthnMethodPkcs7,
				ClientDeployEnvironment: enums.ClientDeployEnvironmentAlibabaCloudEcs,
				// ApplicationFederatedCredentialName intentionally empty
			},
		},
	}

	_, err := prov.refreshCredential(context.Background())
	if err == nil {
		t.Fatal("expected error for PKCS7 without ApplicationFederatedCredentialName")
	}
	if !errors.HasCode(err, constants.ApplicationFederatedCredentialNameNotFound) {
		t.Errorf("expected error code %q (dispatched to getPkcs7Credential), got: %v",
			constants.ApplicationFederatedCredentialNameNotFound, err)
	}
}

// TestBoundary_RefreshCredential_DispatchOidc verifies that AuthnMethod=Oidc
// dispatches to getOidcCredential (which delegates to getOidcCredentialForDeployEnv).
// With KUBERNETES deploy env and no token path configured, it attempts to read
// the default K8s path — confirming the OIDC dispatch chain .
func TestBoundary_RefreshCredential_DispatchOidc(t *testing.T) {
	if _, statErr := os.Stat(constants.K8sServiceAccountTokenPath); statErr != nil {
		// K8s token file does not exist — error should mention the default K8s path.
		prov := &IDaaSMachineCredentialProvider{
			config: &config.IDaaSClientConfig{
				AuthnConfiguration: &config.IdentityAuthenticationConfiguration{
					AuthnMethod:                        enums.TokenAuthnMethodOidc,
					ApplicationFederatedCredentialName: "fc-name",
					ClientDeployEnvironment:            enums.ClientDeployEnvironmentKubernetes,
				},
			},
			httpClient: &mockHttpClientForImpl{},
		}
		_, err := prov.refreshCredential(context.Background())
		if err == nil {
			t.Fatal("expected error for OIDC with default K8s path (file does not exist)")
		}
		if !strings.Contains(err.Error(), constants.K8sServiceAccountTokenPath) {
			t.Errorf("expected error to mention default K8s path %q, got: %v",
				constants.K8sServiceAccountTokenPath, err)
		}
		return
	}

	// K8s token file exists — provide a mock so the dispatch chain completes.
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
				AuthnMethod:                        enums.TokenAuthnMethodOidc,
				ApplicationFederatedCredentialName: "fc-name",
				ClientDeployEnvironment:            enums.ClientDeployEnvironmentKubernetes,
			},
		},
		httpClient: mock,
	}
	cred, err := prov.refreshCredential(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred == nil {
		t.Fatal("expected non-nil credential from OIDC dispatch")
	}
}
