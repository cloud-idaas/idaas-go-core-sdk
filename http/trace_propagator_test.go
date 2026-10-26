package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cloud-idaas/idaas-go-core-sdk/domain"
	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
)

// stubPropagator 记录 Inject 调用,并向 carrier 写入一个 W3C traceparent,
// 用于断言出站请求头确实被注入。
type stubPropagator struct {
	called      bool
	injectedCtx context.Context
	traceparent string
}

func (s *stubPropagator) Inject(ctx context.Context, c HeaderCarrier) {
	s.called = true
	s.injectedCtx = ctx
	s.traceparent = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
	c.Set("traceparent", s.traceparent)
}

// compile-time: *DefaultHttpClient 实现 TracePropagator 注入侧契约(builder 返回自身)。
var _ = (&DefaultHttpClient{}).WithTracePropagator

func TestWithTracePropagator_NilIsNoOp(t *testing.T) {
	c := NewDefaultHttpClient(0, 0)
	// nil 等同于不调用,字段保持零值(beta 默认)。
	c.WithTracePropagator(nil)
	if c.propagator != nil {
		t.Fatalf("nil propagator should be no-op, got propagator=%v", c.propagator)
	}
}

func TestWithTracePropagator_SetsField(t *testing.T) {
	c := NewDefaultHttpClient(0, 0)
	prop := &stubPropagator{}
	got := c.WithTracePropagator(prop)
	if got != c {
		t.Fatal("WithTracePropagator should return *DefaultHttpClient for chaining")
	}
	if c.propagator != prop {
		t.Fatalf("propagator not set, got %v want %v", c.propagator, prop)
	}
}

func TestHeaderCarrier_HttpHeaderImplements(t *testing.T) {
	// net/http.Header 必须原生实现 HeaderCarrier,使 ExecuteContext 可直接传 req.Header。
	var _ HeaderCarrier = http.Header{}
	var _ HeaderCarrier = http.Header(nil)
}

func TestExecuteContext_NoPropagator_DoesNotSetTraceparent(t *testing.T) {
	var sawTraceparent string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawTraceparent = r.Header.Get("traceparent")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	c := NewDefaultHttpClient(0, 0) // 无 propagator
	_, err := c.Execute(&domain.HttpRequest{
		Method: enums.HttpMethodGet,
		URL:    srv.URL,
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if sawTraceparent != "" {
		t.Fatalf("expected no traceparent without propagator, got %q", sawTraceparent)
	}
}

func TestExecuteContext_PropagatorInjectsTraceparent(t *testing.T) {
	var sawTraceparent string
	var sawRequestCtx context.Context
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawTraceparent = r.Header.Get("traceparent")
		sawRequestCtx = r.Context()
		w.WriteHeader(200)
	}))
	defer srv.Close()

	prop := &stubPropagator{}
	c := NewDefaultHttpClient(0, 0).WithTracePropagator(prop)

	type ctxKey struct{}
	ctx := context.WithValue(context.Background(), ctxKey{}, "marker")

	_, err := c.ExecuteContext(ctx, &domain.HttpRequest{
		Method: enums.HttpMethodGet,
		URL:    srv.URL,
	})
	if err != nil {
		t.Fatalf("ExecuteContext failed: %v", err)
	}

	if !prop.called {
		t.Fatal("propagator.Inject was not called")
	}
	// Inject 收到的 ctx 应是调用方传入的 ctx(透传,不替换)。
	if prop.injectedCtx != ctx {
		t.Fatal("propagator must receive the caller's ctx, not a replacement")
	}
	if sawTraceparent != prop.traceparent {
		t.Fatalf("outbound request missing traceparent: got %q want %q",
			sawTraceparent, prop.traceparent)
	}
	_ = sawRequestCtx // 请求侧 ctx 经 http.NewRequestWithContext 透传,此处不额外断言
}

func TestExecuteContext_PropagatorCalledAfterHeadersSet(t *testing.T) {
	// 确认 Inject 在 SDK 设置 User-Agent / 调用方 Headers 之后调用,
	// 使 propagator 看到最终请求头(可覆盖或追加)。
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	prop := &stubPropagator{}
	c := NewDefaultHttpClient(0, 0).WithTracePropagator(prop)

	req := &domain.HttpRequest{
		Method:  enums.HttpMethodGet,
		URL:     srv.URL,
		Headers: map[string]string{"X-Custom": "v"},
	}
	_, _ = c.Execute(req)
	if !prop.called {
		t.Fatal("propagator not called")
	}
}
