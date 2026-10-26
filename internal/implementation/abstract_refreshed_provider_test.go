package implementation

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/cloud-idaas/idaas-go-core-sdk/cache"
	"github.com/cloud-idaas/idaas-go-core-sdk/credential"
	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
)

// stubCredential 是 IDaaSCredential 的最小实现,用于测试抽象刷新提供者。
// 字段值均为无意义占位,非真实凭证。
type stubCredential struct {
	label string
}

func (c *stubCredential) GetAccessToken() string  { return c.label }
func (c *stubCredential) GetTokenType() string    { return "Bearer" }
func (c *stubCredential) GetExpiresIn() int64     { return 3600 }
func (c *stubCredential) GetScope() string        { return "openid" }
func (c *stubCredential) GetRefreshToken() string { return "" }
func (c *stubCredential) String() string          { return "stub(redacted)" }

// mockClock 实现 cache.Clock,支持时间推进,用于触发 stale/expire 分支。
// 用 mutex 保护 t,因为 ALLOW 过期分支会触发后台异步刷新 goroutine 并发读时钟,
// 测试主 goroutine 同时 Advance,无锁会触发 -race。
type mockClock struct {
	mu sync.RWMutex
	t  time.Time
}

func (m *mockClock) Now() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.t
}

func (m *mockClock) Advance(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.t = m.t.Add(d)
}

// TestAbstractRefreshedCredentialProvider_Success 验证成功路径:GetCredential
// 返回刷新函数提供的凭证;Invalidate 使缓存失效后再次获取会重新刷新;
// SetScope/Close 不 panic。
func TestAbstractRefreshedCredentialProvider_Success(t *testing.T) {
	mock := &mockClock{t: time.Now()}
	calls := 0
	cred := &stubCredential{label: "cred-one"}
	refreshFunc := func(context.Context) (*cache.RefreshResult[credential.IDaaSCredential], error) {
		calls++
		expiresAt := mock.Now().Add(10 * time.Minute)
		return &cache.RefreshResult[credential.IDaaSCredential]{
			Value:        cred,
			StaleTime:    expiresAt.Add(-2 * time.Minute), // 80% 存活
			PrefetchTime: expiresAt.Add(-3 * time.Minute), // 67% 存活
			ExpiresAt:    expiresAt,
		}, nil
	}

	p := NewAbstractRefreshedCredentialProvider(refreshFunc, enums.StaleValueBehaviorAllow)
	p.supplier.WithClock(mock)
	defer p.Close()

	got, err := p.GetCredential()
	if err != nil {
		t.Fatalf("GetCredential success path failed: %v", err)
	}
	if got.GetAccessToken() != "cred-one" {
		t.Errorf("expected cred-one, got %s", got.GetAccessToken())
	}
	if calls != 1 {
		t.Errorf("expected 1 refresh call, got %d", calls)
	}

	// 第二次命中缓存,不应再次刷新(无 Invalidate)。
	got2, err := p.GetCredential()
	if err != nil {
		t.Fatalf("cached GetCredential failed: %v", err)
	}
	if got2.GetAccessToken() != "cred-one" {
		t.Errorf("expected cached cred-one, got %s", got2.GetAccessToken())
	}
	if calls != 1 {
		t.Errorf("cache hit should not refresh, calls=%d", calls)
	}

	// Invalidate 后下次获取重新刷新。
	p.Invalidate()
	_, err = p.GetCredential()
	if err != nil {
		t.Fatalf("GetCredential after Invalidate failed: %v", err)
	}
	if calls != 2 {
		t.Errorf("expected refresh after Invalidate, calls=%d", calls)
	}

	// SetScope 不 panic(供应商非 nil 分支)。
	p.SetScope("api.example.com|read")
}

// TestAbstractRefreshedCredentialProvider_ErrorNilResult 刷新返回 (nil, err) 时
// GetCredential 返回 (nil, err),走 result==nil 分支。
func TestAbstractRefreshedCredentialProvider_ErrorNilResult(t *testing.T) {
	boom := errors.New("refresh failed")
	refreshFunc := func(context.Context) (*cache.RefreshResult[credential.IDaaSCredential], error) {
		return nil, boom
	}
	mock := &mockClock{t: time.Now()}
	p := NewAbstractRefreshedCredentialProvider(refreshFunc, enums.StaleValueBehaviorAllow)
	p.supplier.WithClock(mock)
	defer p.Close()

	got, err := p.GetCredential()
	if err == nil {
		t.Fatal("expected error from failed refresh")
	}
	if !errors.Is(err, boom) {
		t.Errorf("expected wrapped boom error, got %v", err)
	}
	if got != nil {
		t.Errorf("expected nil credential on error, got %v", got)
	}
}

// TestAbstractRefreshedCredentialProvider_DegradedStaleValue 验证降级路径:
// ALLOW 策略下凭证过期时,GetCredentialWithContext 返回 (旧值, ErrStaleCredentialReturned),
// 调用方同时拿到降级凭证和 staleness 信号。这覆盖 GetCredentialWithContext 的
// err!=nil && result!=nil 分支。
func TestAbstractRefreshedCredentialProvider_DegradedStaleValue(t *testing.T) {
	mock := &mockClock{t: time.Now()}
	cred := &stubCredential{label: "cred-degraded"}
	refreshFunc := func(context.Context) (*cache.RefreshResult[credential.IDaaSCredential], error) {
		expiresAt := mock.Now().Add(1 * time.Minute)
		return &cache.RefreshResult[credential.IDaaSCredential]{
			Value:        cred,
			StaleTime:    expiresAt.Add(-12 * time.Second), // 80% 存活
			PrefetchTime: expiresAt.Add(-20 * time.Second), // 67% 存活
			ExpiresAt:    expiresAt,
		}, nil
	}

	p := NewAbstractRefreshedCredentialProvider(refreshFunc, enums.StaleValueBehaviorAllow)
	p.supplier.WithClock(mock)
	defer p.Close()

	// 首次获取:缓存成功(ExpiresAt = now+1min)。
	if _, err := p.GetCredential(); err != nil {
		t.Fatalf("initial GetCredential failed: %v", err)
	}

	// 推进时钟超过过期时间 → ALLOW 返回 (cached, ErrStaleCredentialReturned)。
	mock.Advance(2 * time.Minute)
	got, err := p.GetCredential()
	if err == nil {
		t.Fatal("expected ErrStaleCredentialReturned on expired ALLOW credential")
	}
	if !errors.Is(err, cache.ErrStaleCredentialReturned) {
		t.Errorf("expected ErrStaleCredentialReturned, got %v", err)
	}
	// 降级路径应同时返回旧值,而非 nil。
	if got == nil {
		t.Fatal("degraded path should return stale credential, got nil")
	}
	if got.GetAccessToken() != "cred-degraded" {
		t.Errorf("expected degraded cred-degraded, got %s", got.GetAccessToken())
	}
}

// TestAbstractRefreshedCredentialProvider_CloseIdempotent Close 多次调用安全。
func TestAbstractRefreshedCredentialProvider_CloseIdempotent(t *testing.T) {
	mock := &mockClock{t: time.Now()}
	refreshFunc := func(context.Context) (*cache.RefreshResult[credential.IDaaSCredential], error) {
		return &cache.RefreshResult[credential.IDaaSCredential]{
			Value:     &stubCredential{label: "cred-x"},
			ExpiresAt: mock.Now().Add(time.Hour),
		}, nil
	}
	p := NewAbstractRefreshedCredentialProvider(refreshFunc, enums.StaleValueBehaviorAllow)
	p.supplier.WithClock(mock)

	if err := p.Close(); err != nil {
		t.Errorf("first Close returned error: %v", err)
	}
	// 多次 Close 安全。
	if err := p.Close(); err != nil {
		t.Errorf("second Close returned error: %v", err)
	}
}
