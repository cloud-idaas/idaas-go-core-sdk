package factory

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"sync"
	"testing"

	"github.com/cloud-idaas/idaas-go-core-sdk/domain"
	"github.com/cloud-idaas/idaas-go-core-sdk/provider"
)

// scopeCapturingHttpClient 记录每次 token 请求 form 里的 scope，并返回一个合法的 token 响应。
type scopeCapturingHttpClient struct {
	mu     sync.Mutex
	scopes []string
}

func (c *scopeCapturingHttpClient) Execute(req *domain.HttpRequest) (*domain.HttpResponse, error) {
	return c.ExecuteContext(context.Background(), req)
}

func (c *scopeCapturingHttpClient) ExecuteContext(_ context.Context, req *domain.HttpRequest) (*domain.HttpResponse, error) {
	form, err := url.ParseQuery(fmt.Sprint(req.Body))
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.scopes = append(c.scopes, form.Get("scope"))
	c.mu.Unlock()
	return &domain.HttpResponse{
		StatusCode: 200,
		Body:       []byte(`{"access_token":"at","token_type":"Bearer","expires_in":3600}`),
	}, nil
}

func (c *scopeCapturingHttpClient) Get(string, map[string]string) (*domain.HttpResponse, error) {
	return nil, fmt.Errorf("unexpected GET")
}

func (c *scopeCapturingHttpClient) Post(string, map[string]string, interface{}) (*domain.HttpResponse, error) {
	return nil, fmt.Errorf("unexpected Post")
}

// TestGetIDaaSCredentialProviderByScope_SendsRequestedScope 回归：
// ByScope 返回的 provider 必须向 token endpoint 请求调用方传入的 scope，而不是配置里的默认 scope。
func TestGetIDaaSCredentialProviderByScope_SendsRequestedScope(t *testing.T) {
	Reset()
	defer Reset()
	os.Setenv("CLOUD_IDAAS_CLIENT_SECRET", "test_secret")
	defer os.Unsetenv("CLOUD_IDAAS_CLIENT_SECRET")

	f := GetInstance()
	if err := f.Initialize(validTestConfig()); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	// Initialize 已用真实 client 预热了默认 scope 的 provider：换成捕获 client 后清空缓存。
	capture := &scopeCapturingHttpClient{}
	f.mu.Lock()
	f.httpClient = capture
	f.providers = make(map[string]provider.IDaaSCredentialProvider)
	f.mu.Unlock()

	const requested = "api://other.example.com|write"
	p, err := f.GetIDaaSCredentialProviderByScope(requested)
	if err != nil {
		t.Fatalf("GetIDaaSCredentialProviderByScope failed: %v", err)
	}
	if _, err := p.GetCredential(); err != nil {
		t.Fatalf("GetCredential failed: %v", err)
	}

	// 空 scope 回落到配置的默认 scope。
	dp, err := f.GetIDaaSCredentialProviderByScope("")
	if err != nil {
		t.Fatalf("GetIDaaSCredentialProvider (default) failed: %v", err)
	}
	if _, err := dp.GetCredential(); err != nil {
		t.Fatalf("GetCredential (default) failed: %v", err)
	}

	want := []string{requested, validTestConfig().Scope}
	if fmt.Sprint(capture.scopes) != fmt.Sprint(want) {
		t.Fatalf("token request scopes = %q, want %q", capture.scopes, want)
	}
}
