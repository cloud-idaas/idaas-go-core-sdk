package authentication

import (
	"context"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloud-idaas/idaas-go-core-sdk/domain"
	"github.com/cloud-idaas/idaas-go-core-sdk/oauth2"
)

// countingHumanProvider 返回一个 provider，其 mock IdP 统计调用次数并按 respond 应答。
func countingHumanProvider(t *testing.T, cachePath string, respond func(n int64) *domain.HttpResponse) (*HumanFederatedOidcTokenProvider, *int64) { //nolint:gocritic // unnamedResult:函数体内以局部变量计数并被闭包捕获地址,命名返回值反而引入同名遮蔽
	t.Helper()
	var calls int64
	mock := &mockAuthHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return respond(atomic.AddInt64(&calls, 1)), nil
		},
	}
	return &HumanFederatedOidcTokenProvider{
		clientId:                    "test-client-id",
		scope:                       DefaultScope,
		tokenEndpoint:               "https://token.example.com",
		deviceAuthorizationEndpoint: "https://device.example.com",
		localHumanCachePath:         cachePath,
		httpClient:                  mock,
		oauth2Util:                  oauth2.NewOAuth2TokenUtil(mock),
	}, &calls
}

func getConcurrently(t *testing.T, p *HumanFederatedOidcTokenProvider, n int, want string) {
	t.Helper()
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cred, err := p.GetCredentialWithContext(context.Background())
			if err != nil {
				t.Errorf("GetCredential failed: %v", err)
				return
			}
			if cred.GetAccessToken() != want {
				t.Errorf("access token = %q, want %q", cred.GetAccessToken(), want)
			}
		}()
	}
	wg.Wait()
}

// TestHumanProvider_ValidTokenNoIdPCalls 回归：token 有效期内重复获取凭证不得访问 IdP。
// 修复前第二次起每次调用都用 refresh token 请求 IdP。
func TestHumanProvider_ValidTokenNoIdPCalls(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), "human-cache.json")
	writeBoundaryCacheFile(t, cachePath, "test-cached-at", "test-cached-rt", 3600, time.Now())

	p, calls := countingHumanProvider(t, cachePath, func(int64) *domain.HttpResponse {
		return &domain.HttpResponse{StatusCode: 200, Body: makeBoundaryTokenJSON("test-unexpected", "rt", 3600)}
	})

	for i := 0; i < 10; i++ {
		cred, err := p.GetCredentialWithContext(context.Background())
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		if cred.GetAccessToken() != "test-cached-at" {
			t.Fatalf("call %d: access token = %q, want test-cached-at", i, cred.GetAccessToken())
		}
	}
	getConcurrently(t, p, 20, "test-cached-at")

	if n := atomic.LoadInt64(calls); n != 0 {
		t.Errorf("IdP calls = %d, want 0 while the token is valid", n)
	}
}

// TestHumanProvider_ConcurrentFirstCallsSingleDeviceFlow 回归：并发首次调用只跑一次 device flow，
// 之后 token 有效期内不再访问 IdP。
func TestHumanProvider_ConcurrentFirstCallsSingleDeviceFlow(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), "human-cache.json")
	var deviceCodeCalls int64
	p, calls := countingHumanProvider(t, cachePath, func(n int64) *domain.HttpResponse {
		if n == 1 {
			atomic.AddInt64(&deviceCodeCalls, 1)
			return &domain.HttpResponse{StatusCode: 200, Body: makeBoundaryDeviceCodeJSON("dev-code", 5, 1)}
		}
		return &domain.HttpResponse{StatusCode: 200, Body: makeBoundaryTokenJSON("test-device-at", "test-device-rt", 3600)}
	})

	getConcurrently(t, p, 20, "test-device-at")
	afterFirst := atomic.LoadInt64(calls)
	if afterFirst != 2 {
		t.Errorf("IdP calls after concurrent first calls = %d, want 2 (device code + token)", afterFirst)
	}

	for i := 0; i < 10; i++ {
		if _, err := p.GetCredentialWithContext(context.Background()); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if n := atomic.LoadInt64(calls); n != afterFirst {
		t.Errorf("IdP calls grew from %d to %d while the token is valid", afterFirst, n)
	}
}
