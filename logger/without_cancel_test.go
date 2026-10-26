package logger

import (
	"context"
	"testing"
	"time"
)

// TestWithoutCancel_PreservesValues_IgnoresCancel 验证 1.18 polyfill 语义:
//   - Value 链透传 parent(trace span/requestId 保留)
//   - Deadline() 返零值+false(无截止)
//   - Done() 返 nil chan(select{<-ctx.Done()} 永不触发)
//   - Err() 返 nil(不视为已取消)——即使 parent 已 cancel
//
// 这是新 worker(runRefreshAndCommit /runAzureFetch) 日志 ctx
// 不会因 parent 取消而拒记的硬保证。
func TestWithoutCancel_PreservesValues_IgnoresCancel(t *testing.T) {
	type ctxKey string
	const k ctxKey = "requestId"

	parent, cancel := context.WithCancel(context.Background())
	parent = context.WithValue(parent, k, "req-123")
	// 先构造一个有 deadline 的 parent,验证 polyfill 不继承 deadline
	deadlineParent, dcancel := context.WithDeadline(parent, time.Now().Add(10*time.Second))
	defer dcancel()

	nc := WithoutCancel(deadlineParent)

	// Value 透传
	if got := nc.Value(k); got != "req-123" {
		t.Errorf("Value(k): got %v, want req-123 (parent Value chain must pass through)", got)
	}

	// Deadline 被清除
	if _, ok := nc.Deadline(); ok {
		t.Error("Deadline(): got ok=true, want false (polyfill must not inherit parent deadline)")
	}

	// Done 返 nil
	if ch := nc.Done(); ch != nil {
		t.Errorf("Done(): got non-nil chan %v, want nil (must not respond to cancel)", ch)
	}

	// 取消 parent 后,polyfill 仍不报取消
	cancel()
	if err := nc.Err(); err != nil {
		t.Errorf("Err() after parent cancel: got %v, want nil (must ignore parent cancellation)", err)
	}
	if ch := nc.Done(); ch != nil {
		t.Errorf("Done() after parent cancel: got %v, want nil", ch)
	}

	// select{<-ctx.Done()} 永不触发:用 select default 验证非阻塞
	select {
	case <-nc.Done():
		t.Error("recv from Done() should never return (polyfill ignores cancel)")
	default:
		// 正确:Done() 永不触发
	}
}

// TestWithoutCancel_NilParentFallback 验证防御:nil parent 不 panic、等价 Background 语义。
func TestWithoutCancel_NilParentFallback(t *testing.T) {
	nc := WithoutCancel(nil) //nolint:staticcheck // SA1012: 故意传 nil,验证防御性回退不 panic
	if err := nc.Err(); err != nil {
		t.Errorf("Err(): got %v, want nil", err)
	}
	if ch := nc.Done(); ch != nil {
		t.Errorf("Done(): got %v, want nil", ch)
	}
	if _, ok := nc.Deadline(); ok {
		t.Error("Deadline(): got ok=true, want false")
	}
}

// TestWithoutCancel_NestedPreservesAllValues 验证多层 Value 链全透传
// (trace span/requestId/userId 等多 key 嵌套场景)。
func TestWithoutCancel_NestedPreservesAllValues(t *testing.T) {
	type k1 string
	type k2 string
	parent := context.Background()
	parent = context.WithValue(parent, k1("span"), "span-abc")
	parent = context.WithValue(parent, k2("uid"), "u-42")

	nc := WithoutCancel(parent)

	if got := nc.Value(k1("span")); got != "span-abc" {
		t.Errorf("Value(span): got %v, want span-abc", got)
	}
	if got := nc.Value(k2("uid")); got != "u-42" {
		t.Errorf("Value(uid): got %v, want u-42", got)
	}
}
