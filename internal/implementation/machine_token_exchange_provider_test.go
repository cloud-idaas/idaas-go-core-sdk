package implementation

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/cloud-idaas/idaas-go-core-sdk/config"
	"github.com/cloud-idaas/idaas-go-core-sdk/constants"
	"github.com/cloud-idaas/idaas-go-core-sdk/credential"
	"github.com/cloud-idaas/idaas-go-core-sdk/domain"
	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
	idaaserrors "github.com/cloud-idaas/idaas-go-core-sdk/errors"
	"github.com/cloud-idaas/idaas-go-core-sdk/provider"
)

// newExchangeTestConfig 返回 client_secret_post 配置，secret 来自环境变量 X。
func newExchangeTestConfig(t *testing.T) *config.IDaaSClientConfig {
	t.Helper()
	t.Setenv("X", "secret")
	return &config.IDaaSClientConfig{
		ClientId:      "cid",
		TokenEndpoint: "https://token.example.com",
		AuthnConfiguration: &config.IdentityAuthenticationConfiguration{
			AuthnMethod:            enums.TokenAuthnMethodClientSecretPost,
			ClientSecretEnvVarName: "X",
		},
	}
}

func TestNewIDaaSMachineTokenExchangeCredentialProvider(t *testing.T) {
	mock := &mockHttpClientForImpl{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 200, Body: makeTokenResponseBody(testTokenValue)}, nil
		},
	}
	prov := NewIDaaSMachineTokenExchangeCredentialProvider(newExchangeTestConfig(t), "", mock)
	if prov == nil {
		t.Fatal("expected non-nil provider")
	}
	if prov.config == nil || prov.config.ClientId != "cid" || prov.config.TokenEndpoint != "https://token.example.com" {
		t.Errorf("unexpected config: %+v", prov.config)
	}
	if prov.tokenUtil == nil {
		t.Error("expected non-nil tokenUtil")
	}
}

func TestExchangeToken_Success(t *testing.T) {
	mock := &mockHttpClientForImpl{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 200, Body: makeTokenResponseBody(testTokenValue)}, nil
		},
	}
	prov := NewIDaaSMachineTokenExchangeCredentialProvider(newExchangeTestConfig(t), "", mock)

	req := provider.TokenExchangeRequest{
		SubjectToken: "subject-token-val",
		Scope:        "read",
	}
	cred, err := prov.ExchangeToken(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred == nil {
		t.Fatal("expected non-nil credential")
	}
	if cred.GetAccessToken() != testTokenValue {
		t.Errorf("expected '%s', got '%s'", testTokenValue, cred.GetAccessToken())
	}
}

func TestExchangeTokenWithContext_Success(t *testing.T) {
	mock := &mockHttpClientForImpl{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 200, Body: makeTokenResponseBody(testTokenValue)}, nil
		},
	}
	prov := NewIDaaSMachineTokenExchangeCredentialProvider(newExchangeTestConfig(t), "", mock)

	req := provider.TokenExchangeRequest{
		SubjectToken:       "subject-token-val",
		SubjectTokenType:   "urn:ietf:params:oauth:token-type:access_token",
		ActorToken:         "actor-token-val",
		ActorTokenType:     "urn:ietf:params:oauth:token-type:access_token",
		RequestedTokenType: "urn:ietf:params:oauth:token-type:access_token",
		Scope:              "read",
	}
	cred, err := prov.ExchangeTokenWithContext(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred.GetAccessToken() != testTokenValue {
		t.Errorf("expected '%s', got '%s'", testTokenValue, cred.GetAccessToken())
	}
}

func TestExchangeTokenWithContext_DefaultSubjectTokenType(t *testing.T) {
	var capturedForm string
	mock := &mockHttpClientForImpl{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			if req.Body != nil {
				switch b := req.Body.(type) {
				case []byte:
					capturedForm = string(b)
				case string:
					capturedForm = string(b)
				}
			}
			resp := credential.IDaaSTokenResponse{}
			resp.AccessToken = testTokenValue
			resp.TokenType = "Bearer"
			resp.ExpiresIn = 3600
			b, _ := json.Marshal(&resp)
			return &domain.HttpResponse{StatusCode: 200, Body: b}, nil
		},
	}
	prov := NewIDaaSMachineTokenExchangeCredentialProvider(newExchangeTestConfig(t), "", mock)

	req := provider.TokenExchangeRequest{
		SubjectToken: "subject-token-val",
	}
	cred, err := prov.ExchangeTokenWithContext(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred.GetAccessToken() != testTokenValue {
		t.Errorf("expected '%s', got '%s'", testTokenValue, cred.GetAccessToken())
	}
	_ = capturedForm
}

func TestExchangeTokenWithContext_ActorTokenNoType(t *testing.T) {
	mock := &mockHttpClientForImpl{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 200, Body: makeTokenResponseBody(testTokenValue)}, nil
		},
	}
	prov := NewIDaaSMachineTokenExchangeCredentialProvider(newExchangeTestConfig(t), "", mock)

	req := provider.TokenExchangeRequest{
		SubjectToken: "subject-token-val",
		ActorToken:   "actor-token-val",
		// ActorTokenType intentionally empty to test default behavior
	}
	cred, err := prov.ExchangeTokenWithContext(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred.GetAccessToken() != testTokenValue {
		t.Errorf("expected '%s', got '%s'", testTokenValue, cred.GetAccessToken())
	}
}

// TestExchangeTokenWithContext_EmptySubjectToken_RejectedClientSide 锁定 RFC 8693
// subject_token REQUIRED 的客户端拦截：空/纯空白都必须报 SubjectTokenNotFound，
// 且不得向服务端发出任何请求（省往返、负例不依赖服务端严格性）。
func TestExchangeTokenWithContext_EmptySubjectToken_RejectedClientSide(t *testing.T) {
	called := false
	mock := &mockHttpClientForImpl{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			called = true
			return &domain.HttpResponse{StatusCode: 200, Body: makeTokenResponseBody(testTokenValue)}, nil
		},
	}
	prov := NewIDaaSMachineTokenExchangeCredentialProvider(newExchangeTestConfig(t), "", mock)

	for _, blank := range []string{"", "   ", "\t\n"} {
		_, err := prov.ExchangeTokenWithContext(context.Background(), provider.TokenExchangeRequest{SubjectToken: blank})
		if err == nil {
			t.Fatalf("blank subject_token %q must be rejected client-side", blank)
		}
		if !idaaserrors.HasCode(err, constants.SubjectTokenNotFound) {
			t.Errorf("subject_token=%q: expected code %s, got %v", blank, constants.SubjectTokenNotFound, err)
		}
	}
	if called {
		t.Error("client-side rejection must not send any HTTP request")
	}
}

func TestExchangeTokenWithContext_Error(t *testing.T) {
	mock := &mockHttpClientForImpl{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 401, Body: []byte(`{"error":"invalid_token"}`)}, nil
		},
	}
	prov := NewIDaaSMachineTokenExchangeCredentialProvider(newExchangeTestConfig(t), "", mock)

	req := provider.TokenExchangeRequest{
		SubjectToken: "invalid",
	}
	_, err := prov.ExchangeTokenWithContext(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for 401 response")
	}
}

// Ensure mockHttpClientForImpl satisfies the http.HttpClient interface
var _ interface {
	Execute(req *domain.HttpRequest) (*domain.HttpResponse, error)
} = (*mockHttpClientForImpl)(nil)

// Suppress unused import warnings
var _ = enums.HttpMethodGet
