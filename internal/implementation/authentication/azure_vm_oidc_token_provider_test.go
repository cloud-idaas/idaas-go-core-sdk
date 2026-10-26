package authentication

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloud-idaas/idaas-go-core-sdk/constants"
	"github.com/cloud-idaas/idaas-go-core-sdk/domain"
	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
)

// mockAzureHttpClient 用于捕获请求参数并返回预设响应，实现 http.HttpClient 接口
type mockAzureHttpClient struct {
	executeFn   func(req *domain.HttpRequest) (*domain.HttpResponse, error)
	callCount   int
	lastRequest *domain.HttpRequest
}

func (m *mockAzureHttpClient) Execute(req *domain.HttpRequest) (*domain.HttpResponse, error) {
	m.callCount++
	m.lastRequest = req
	return m.executeFn(req)
}

// ExecuteContext 实现 http.HttpClient.ExecuteContext (M8),测试 mock 忽略 ctx。
func (m *mockAzureHttpClient) ExecuteContext(_ context.Context, req *domain.HttpRequest) (*domain.HttpResponse, error) {
	return m.Execute(req)
}

func (m *mockAzureHttpClient) Get(rawURL string, headers map[string]string) (*domain.HttpResponse, error) {
	return m.Execute(&domain.HttpRequest{Method: enums.HttpMethodGet, URL: rawURL, Headers: headers})
}

func (m *mockAzureHttpClient) Post(rawURL string, headers map[string]string, body interface{}) (*domain.HttpResponse, error) {
	return m.Execute(&domain.HttpRequest{Method: enums.HttpMethodPost, URL: rawURL, Headers: headers, Body: body})
}

// makeAzureImdsResponseBody 构造一个合法的 Azure IMDS JSON 响应体
func makeAzureImdsResponseBody(accessToken string, expiresOn int64) []byte {
	body := map[string]string{
		"access_token":   accessToken,
		"client_id":      "fake-client-id",
		"expires_in":     "3599",
		"expires_on":     strconv.FormatInt(expiresOn, 10),
		"ext_expires_in": "3599",
		"not_before":     strconv.FormatInt(expiresOn-3600, 10),
		"resource":       "https://idaas.example.com",
		"token_type":     "Bearer",
	}
	b, _ := json.Marshal(body)
	return b
}

// makeFakeJwtForAzure 构造一个包含指定 exp 的伪 JWT（与 GCP 测试中保持一致的工具）
func makeFakeJwtForAzure(exp int64) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payloadJson, _ := json.Marshal(map[string]interface{}{"exp": exp, "aud": "https://idaas.example.com"})
	payload := base64.RawURLEncoding.EncodeToString(payloadJson)
	return header + "." + payload + ".signature"
}

func TestAzureVmOidcTokenProvider_GetOidcToken_Success(t *testing.T) {
	expectedToken := makeFakeJwtForAzure(time.Now().Add(time.Hour).Unix())
	expiresOn := time.Now().Add(time.Hour).Unix()

	mock := &mockAzureHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 200, Body: makeAzureImdsResponseBody(expectedToken, expiresOn)}, nil
		},
	}

	provider := NewAzureVmOidcTokenProvider(mock)
	token, err := provider.GetOidcToken()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != expectedToken {
		t.Errorf("token mismatch: want %s, got %s", expectedToken, token)
	}

	// 校验请求方法 / Header
	if mock.lastRequest.Method != enums.HttpMethodGet {
		t.Errorf("expected GET, got %v", mock.lastRequest.Method)
	}
	if got := mock.lastRequest.Headers[constants.HeaderMetadata]; got != constants.HeaderMetadataValueTrue {
		t.Errorf("expected header %s=%s, got %s", constants.HeaderMetadata, constants.HeaderMetadataValueTrue, got)
	}

	// 校验 URL 包含 URL-encoded 固定 resource、api-version 与 IMDS 主机
	wantSubstr := "resource=" + url.QueryEscape(constants.AzureVmManagementResource)
	if !strings.Contains(mock.lastRequest.URL, wantSubstr) {
		t.Errorf("URL missing encoded resource %q, got URL=%s", wantSubstr, mock.lastRequest.URL)
	}
	if !strings.Contains(mock.lastRequest.URL, "api-version=2018-02-01") {
		t.Errorf("URL missing api-version=2018-02-01, got URL=%s", mock.lastRequest.URL)
	}
	if !strings.HasPrefix(mock.lastRequest.URL, "http://169.254.169.254/") {
		t.Errorf("URL should target IMDS 169.254.169.254, got %s", mock.lastRequest.URL)
	}
}

func TestAzureVmOidcTokenProvider_CacheHitWhenNotExpiring(t *testing.T) {
	expectedToken := makeFakeJwtForAzure(time.Now().Add(time.Hour).Unix())
	expiresOn := time.Now().Add(time.Hour).Unix()
	mock := &mockAzureHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 200, Body: makeAzureImdsResponseBody(expectedToken, expiresOn)}, nil
		},
	}

	provider := NewAzureVmOidcTokenProvider(mock)
	if _, err := provider.GetOidcToken(); err != nil {
		t.Fatalf("first call failed: %v", err)
	}
	if _, err := provider.GetOidcToken(); err != nil {
		t.Fatalf("second call failed: %v", err)
	}

	if mock.callCount != 1 {
		t.Errorf("expected 1 HTTP call due to cache hit, got %d", mock.callCount)
	}
}

func TestAzureVmOidcTokenProvider_RefreshWhenSoonExpiring(t *testing.T) {
	// 9 分钟后过期 -> 小于 10 分钟阈值 -> 必须刷新
	soonExpireToken := makeFakeJwtForAzure(time.Now().Add(9 * time.Minute).Unix())
	farExpireToken := makeFakeJwtForAzure(time.Now().Add(time.Hour).Unix())
	soonExpireOn := time.Now().Add(9 * time.Minute).Unix()
	farExpireOn := time.Now().Add(time.Hour).Unix()

	responses := [][]byte{
		makeAzureImdsResponseBody(soonExpireToken, soonExpireOn),
		makeAzureImdsResponseBody(farExpireToken, farExpireOn),
	}
	idx := 0
	mock := &mockAzureHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			body := responses[idx]
			idx++
			return &domain.HttpResponse{StatusCode: 200, Body: body}, nil
		},
	}

	provider := NewAzureVmOidcTokenProvider(mock)
	first, err := provider.GetOidcToken()
	if err != nil {
		t.Fatalf("first call failed: %v", err)
	}
	second, err := provider.GetOidcToken()
	if err != nil {
		t.Fatalf("second call failed: %v", err)
	}

	if first != soonExpireToken {
		t.Errorf("first token mismatch")
	}
	if second != farExpireToken {
		t.Errorf("expected refresh on second call to return new token")
	}
	if mock.callCount != 2 {
		t.Errorf("expected 2 HTTP calls (refresh due to soon expiration), got %d", mock.callCount)
	}
}

func TestAzureVmOidcTokenProvider_FallbackToJwtExpWhenExpiresOnInvalid(t *testing.T) {
	// expires_on 缺失或不可解析时，应回退到 JWT payload 的 exp
	token := makeFakeJwtForAzure(time.Now().Add(time.Hour).Unix())
	body := []byte(fmt.Sprintf(`{"access_token":%q,"expires_on":"not-a-number","token_type":"Bearer"}`, token))

	mock := &mockAzureHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 200, Body: body}, nil
		},
	}

	provider := NewAzureVmOidcTokenProvider(mock)
	if _, err := provider.GetOidcToken(); err != nil {
		t.Fatalf("first call failed: %v", err)
	}
	if _, err := provider.GetOidcToken(); err != nil {
		t.Fatalf("second call failed: %v", err)
	}

	// 用 JWT exp 作为兜底，距离过期还有 1 小时 -> 命中缓存
	if mock.callCount != 1 {
		t.Errorf("expected cache hit via JWT exp fallback, got %d HTTP calls", mock.callCount)
	}
}

func TestAzureVmOidcTokenProvider_NoExpInfoDisablesCache(t *testing.T) {
	// expires_on 无效 + access_token 不是合法 JWT -> 每次都重新拉取
	body := []byte(`{"access_token":"opaque-not-jwt","expires_on":"bad","token_type":"Bearer"}`)
	mock := &mockAzureHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 200, Body: body}, nil
		},
	}

	provider := NewAzureVmOidcTokenProvider(mock)
	for i := 0; i < 3; i++ {
		if _, err := provider.GetOidcToken(); err != nil {
			t.Fatalf("call #%d failed: %v", i+1, err)
		}
	}
	if mock.callCount != 3 {
		t.Errorf("expected 3 HTTP calls (no exp info, no cache), got %d", mock.callCount)
	}
}

func TestAzureVmOidcTokenProvider_HttpError(t *testing.T) {
	mock := &mockAzureHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 400, Body: []byte(`{"error":"invalid_request"}`)}, nil
		},
	}

	provider := NewAzureVmOidcTokenProvider(mock)
	_, err := provider.GetOidcToken()
	if err == nil {
		t.Fatal("expected error for HTTP 400, got nil")
	}
	if !strings.Contains(err.Error(), "400") {
		t.Errorf("error should mention status code 400, got: %v", err)
	}
}

func TestAzureVmOidcTokenProvider_InvalidJson(t *testing.T) {
	mock := &mockAzureHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 200, Body: []byte(`not-a-json-body`)}, nil
		},
	}

	provider := NewAzureVmOidcTokenProvider(mock)
	_, err := provider.GetOidcToken()
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestAzureVmOidcTokenProvider_EmptyAccessToken(t *testing.T) {
	mock := &mockAzureHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 200, Body: []byte(`{"access_token":"","token_type":"Bearer"}`)}, nil
		},
	}

	provider := NewAzureVmOidcTokenProvider(mock)
	_, err := provider.GetOidcToken()
	if err == nil {
		t.Fatal("expected error for empty access_token, got nil")
	}
}

func TestAzureVmIdentityTokenUrlTemplate_FormatsCorrectly(t *testing.T) {
	got := fmt.Sprintf(constants.AzureVmIdentityTokenUrlTemplate, url.QueryEscape(constants.AzureVmManagementResource))
	want := "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com%2F"
	if got != want {
		t.Errorf("URL template mismatch:\n  want: %s\n  got:  %s", want, got)
	}
}

func TestResolveAzureTokenExpiresAt_BoundaryConditions(t *testing.T) {
	tests := []struct {
		name         string
		expiresOnStr string
		jwtToken     string
		wantExp      int64
		wantZero     bool // true 表示期望返回 0（禁用缓存）
	}{
		{
			name:         "valid expires_on takes precedence",
			expiresOnStr: "1700000000",
			jwtToken:     makeFakeJwtForAzure(1600000000),
			wantExp:      1700000000,
		},
		{
			name:         "expires_on non-numeric falls back to JWT exp",
			expiresOnStr: "not-a-number",
			jwtToken:     makeFakeJwtForAzure(1700000000),
			wantExp:      1700000000,
		},
		{
			name:         "expires_on negative falls back to JWT exp",
			expiresOnStr: "-100",
			jwtToken:     makeFakeJwtForAzure(1700000000),
			wantExp:      1700000000,
		},
		{
			name:         "expires_on empty falls back to JWT exp",
			expiresOnStr: "",
			jwtToken:     makeFakeJwtForAzure(1700000000),
			wantExp:      1700000000,
		},
		{
			name:         "both invalid returns zero",
			expiresOnStr: "invalid",
			jwtToken:     "not-a-jwt",
			wantZero:     true,
		},
		{
			name:         "empty expires_on and invalid JWT returns zero",
			expiresOnStr: "",
			jwtToken:     "",
			wantZero:     true,
		},
		{
			name:         "expires_on zero falls back to JWT exp",
			expiresOnStr: "0",
			jwtToken:     makeFakeJwtForAzure(1700000000),
			wantExp:      1700000000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveAzureTokenExpiresAt(tt.expiresOnStr, tt.jwtToken)
			if tt.wantZero {
				if got != 0 {
					t.Errorf("expected 0 (cache disabled), got %d", got)
				}
			} else {
				if got != tt.wantExp {
					t.Errorf("expected %d, got %d", tt.wantExp, got)
				}
			}
		})
	}
}

// ---singleflight / worker gate tests ---

// ctxAwareAzureMock 是线程安全、ctx 感知的 Azure IMDS mock,满足 -race。
// release 字段非 nil 时,ExecuteContext 在响应前阻塞于 release(模拟慢 IMDS),
// 并在 ctx 取消时返回 ctx.Err()(用于 baseCtx 取消传播测试)。
type ctxAwareAzureMock struct {
	callCount int32
	release   chan struct{}
	respondFn func(req *domain.HttpRequest) (*domain.HttpResponse, error)
	panicFn   func(req *domain.HttpRequest) // 非 nil 时 ExecuteContext 内 panic
}

func (m *ctxAwareAzureMock) Execute(req *domain.HttpRequest) (*domain.HttpResponse, error) {
	return m.ExecuteContext(context.Background(), req)
}

func (m *ctxAwareAzureMock) ExecuteContext(ctx context.Context, req *domain.HttpRequest) (*domain.HttpResponse, error) {
	atomic.AddInt32(&m.callCount, 1)
	if m.panicFn != nil {
		m.panicFn(req)
	}
	if m.release != nil {
		select {
		case <-m.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return m.respondFn(req)
}

func (m *ctxAwareAzureMock) Get(rawURL string, headers map[string]string) (*domain.HttpResponse, error) {
	return m.Execute(&domain.HttpRequest{Method: enums.HttpMethodGet, URL: rawURL, Headers: headers})
}

func (m *ctxAwareAzureMock) Post(rawURL string, headers map[string]string, body interface{}) (*domain.HttpResponse, error) {
	return m.Execute(&domain.HttpRequest{Method: enums.HttpMethodPost, URL: rawURL, Headers: headers, Body: body})
}

func (m *ctxAwareAzureMock) count() int { return int(atomic.LoadInt32(&m.callCount)) }

// TestAzureVm_ConcurrentExpiry_SingleIMDSHit 验证 singleflight:并发 N 调用
// 在 cache-miss 下仅触发 1 次 IMDS hit,且 waiter 拿到一致 token。
func TestAzureVm_ConcurrentExpiry_SingleIMDSHit(t *testing.T) {
	token := makeFakeJwtForAzure(time.Now().Add(time.Hour).Unix())
	expiresOn := time.Now().Add(time.Hour).Unix()

	mock := &ctxAwareAzureMock{
		release: make(chan struct{}),
		respondFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 200, Body: makeAzureImdsResponseBody(token, expiresOn)}, nil
		},
	}

	provider := NewAzureVmOidcTokenProvider(mock)

	const n = 16
	var wg sync.WaitGroup
	start := make(chan struct{})
	tokens := make([]string, n)
	errs := make([]error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(idx int) {
			defer wg.Done()
			<-start
			tk, e := provider.GetOidcTokenWithContext(context.Background())
			tokens[idx] = tk
			errs[idx] = e
		}(i)
	}
	close(start)
	// 让 worker 真正进入 IMDS 调用(已 atomic 计 1),再放行确保所有 waiter 落在同一 inflight。
	time.Sleep(20 * time.Millisecond)
	close(mock.release)
	wg.Wait()

	if got := mock.count(); got != 1 {
		t.Errorf("singleflight broken: IMDS hit %d times, want 1", got)
	}
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Errorf("goroutine %d got err: %v", i, errs[i])
		}
		if tokens[i] != token {
			t.Errorf("goroutine %d token mismatch: want %s, got %s", i, token, tokens[i])
		}
	}
}

// TestAzureVm_LeaderCtxCancel_WorkerCompletes 验证 leader 在 worker 在飞时取消
// caller ctx → waiter 经 select{inf.done|ctx.Done()} 返回 ctx.Err();worker 仍 detached
// 完成,结果提交缓存供后续调用拿到(同语义)。
func TestAzureVm_LeaderCtxCancel_WorkerCompletes(t *testing.T) {
	token := makeFakeJwtForAzure(time.Now().Add(time.Hour).Unix())
	expiresOn := time.Now().Add(time.Hour).Unix()

	mock := &ctxAwareAzureMock{
		release: make(chan struct{}),
		respondFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 200, Body: makeAzureImdsResponseBody(token, expiresOn)}, nil
		},
	}

	provider := NewAzureVmOidcTokenProvider(mock)
	ctx, cancel := context.WithCancel(context.Background())
	type res struct {
		t   string
		err error
	}
	leaderCh := make(chan res, 1)
	go func() {
		tk, e := provider.GetOidcTokenWithContext(ctx)
		leaderCh <- res{tk, e}
	}()

	time.Sleep(20 * time.Millisecond) // 等 leader 占 inflight 并进入 IMDS(release 阻塞)
	begin := time.Now()
	cancel()
	select {
	case got := <-leaderCh:
		if got.err == nil {
			t.Fatal("expected ctx.Canceled after caller cancel, got nil err")
		}
		if !errors.Is(got.err, context.Canceled) {
			t.Errorf("expected errors.Is(context.Canceled), got: %v", got.err)
		}
		if got.t != "" {
			t.Errorf("expected empty token on cancel, got: %s", got.t)
		}
		if time.Since(begin) > 500*time.Millisecond {
			t.Errorf("leader blocked %v after cancel; expected prompt return", time.Since(begin))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("leader did not return within 2s after caller cancel")
	}

	// 放行 worker,确认其 detached 完成、结果提交缓存供后续调用。
	close(mock.release)
	// 后续调用应命中缓存(worker 已提交),不再打 IMDS。
	got2, err := provider.GetOidcTokenWithContext(context.Background())
	if err != nil {
		t.Fatalf("subsequent Get after worker commit failed: %v", err)
	}
	if got2 != token {
		t.Errorf("expected cached token %s from detached worker commit, got: %s", token, got2)
	}
	if c := mock.count(); c != 1 {
		t.Errorf("expected exactly 1 IMDS hit (detached worker), got %d", c)
	}
}

// TestAzureVm_PanicReleasesWaiters 验证:worker 顶层 recover 写非 nil
// err(AzureVmIdentityTokenFetchFailed)并强制 closeDone,waiter 不死锁、不拿 ("",nil)。
//
// 门控要点:leader 的 IMDS 调用先阻塞在 release 上,让其余 waiter 全部注册到同一
// inflight 槽(否则 panic-on-first-call 会让 leader 的在飞窗口近乎零,后到的 waiter
// 观察 inflight==nil 退化为新 leader —— 这是 singleflight 的正确语义而非 bug,但会使
// count 断言不稳)。放行 release 后 respondFn panic,验证 recover 释放所有 waiter。
func TestAzureVm_PanicReleasesWaiters(t *testing.T) {
	mock := &ctxAwareAzureMock{
		release: make(chan struct{}),
		// panicFn 留 nil:让 ExecuteContext 先过 release 门控再 panic,
		// 保证所有 waiter 在 leader panic 前已注册为 inflight waiter。
		respondFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			panic("injected IMDS panic")
		},
	}

	provider := NewAzureVmOidcTokenProvider(mock)

	const n = 8
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make([]error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(idx int) {
			defer wg.Done()
			<-start
			_, e := provider.GetOidcTokenWithContext(context.Background())
			errs[idx] = e
		}(i)
	}
	close(start)
	// 让 leader 进入 ExecuteContext 并阻塞在 release,其余 waiter 注册到同一 inflight。
	time.Sleep(20 * time.Millisecond)
	close(mock.release)
	wg.Wait()

	// 所有 waiter 须拿到非 nil err(panic recovered),不死锁(已 wg.Wait 返回)。
	for i := 0; i < n; i++ {
		if errs[i] == nil {
			t.Errorf("goroutine %d: expected panic-recovered error, got nil", i)
		} else {
			var ce interface{ ErrorCode() string }
			if errors.As(errs[i], &ce) && ce.ErrorCode() != constants.AzureVmIdentityTokenFetchFailed {
				t.Errorf("goroutine %d: error code = %s, want %s", i, ce.ErrorCode(), constants.AzureVmIdentityTokenFetchFailed)
			}
		}
	}
	// singleflight 严格语义下 panic 也只 hit 1 次(leader 唯一 spawn,waiter 不 spawn):
	// 门控保证所有 waiter 在 leader panic 前已注册为 inflight waiter,不会退化为新 leader。
	if c := mock.count(); c != 1 {
		t.Errorf("expected exactly 1 IMDS hit under singleflight (panic path), got %d", c)
	}
	// 关键:inflight 已被 worker 清掉(否则后续调用会走 waiter 死等)。
	provider.mu.Lock()
	inf := provider.inflight
	provider.mu.Unlock()
	if inf != nil {
		t.Errorf("inflight should be cleared after panic recovery, got: %v", inf)
	}
}

// TestAzureVm_BaseContextCancel_StopsWorker 验证//17:baseCtx
// 取消传播到 worker 的 refreshCtx(WithTimeout(baseCtx,...)),ExecuteContext 看到
// ctx.Done 提前返回,worker 不挂到 imdsTimeout,且 waiter 经 inf.done 拿到 ctx.Err()。
func TestAzureVm_BaseContextCancel_StopsWorker(t *testing.T) {
	token := makeFakeJwtForAzure(time.Now().Add(time.Hour).Unix())
	expiresOn := time.Now().Add(time.Hour).Unix()

	mock := &ctxAwareAzureMock{
		release: make(chan struct{}),
		respondFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 200, Body: makeAzureImdsResponseBody(token, expiresOn)}, nil
		},
	}

	baseCtx, baseCancel := context.WithCancel(context.Background())
	provider := NewAzureVmOidcTokenProvider(mock).
		WithImdsTimeout(30 * time.Second). // 长超时,靠 baseCtx 取消而非超时触发
		WithBaseContext(baseCtx)

	type res struct {
		t   string
		err error
	}
	leaderCh := make(chan res, 1)
	go func() {
		tk, e := provider.GetOidcTokenWithContext(context.Background())
		leaderCh <- res{tk, e}
	}()

	time.Sleep(20 * time.Millisecond) // 等 worker 进入 IMDS(release 阻塞,ctx 未取消)
	begin := time.Now()
	baseCancel()

	select {
	case got := <-leaderCh:
		// leader 用 Background ctx,worker ctx 取消后提交 err(ctx.Err());leader 经 inf.done 拿到。
		if got.err == nil {
			t.Fatal("expected error from baseCtx-canceled worker, got nil")
		}
		if time.Since(begin) > 500*time.Millisecond {
			t.Errorf("worker took %v to observe baseCtx cancel", time.Since(begin))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("leader did not return within 2s after baseCtx cancel (worker not stopped)")
	}

	// 放行 release(防 goroutine 泄漏:ExecuteContext 的 select 在 ctx.Done 后已返回,
	// release 不再被读;close 仅为清理)。
	close(mock.release)
}
