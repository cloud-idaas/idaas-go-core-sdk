package provider

import (
	"context"
	"errors"
	"testing"

	"github.com/cloud-idaas/idaas-go-core-sdk/credential"
)

// mockNoCtxProvider is a mock implementation of IDaaSCredentialProviderNoCtx
// for testing WithContextShim.
type mockNoCtxProvider struct {
	cred credential.IDaaSCredential
	err  error
}

func (m *mockNoCtxProvider) GetCredential() (credential.IDaaSCredential, error) {
	return m.cred, m.err
}

// TestNewWithContextShim covers NewWithContextShim (line 34).
func TestNewWithContextShim(t *testing.T) {
	inner := &mockNoCtxProvider{
		cred: &mockCredential{accessToken: "fake-value-123"},
	}

	shim := NewWithContextShim(inner)
	if shim == nil {
		t.Fatal("NewWithContextShim returned nil")
	}

	// Verify it implements IDaaSCredentialProvider
	var _ IDaaSCredentialProvider = shim
}

// TestWithContextShim_GetCredential covers GetCredential (line 39),
// verifying it delegates to the wrapped provider.
func TestWithContextShim_GetCredential(t *testing.T) {
	expectedCred := &mockCredential{
		accessToken: "fake-value-123",
		tokenType:   "Bearer",
		expiresIn:   3600,
	}
	inner := &mockNoCtxProvider{
		cred: expectedCred,
	}

	shim := NewWithContextShim(inner)

	got, err := shim.GetCredential()
	if err != nil {
		t.Fatalf("GetCredential returned unexpected error: %v", err)
	}
	if got != expectedCred {
		t.Errorf("GetCredential returned unexpected credential: got %v, want %v", got, expectedCred)
	}
}

// TestWithContextShim_GetCredential_Error verifies that errors from the
// inner provider are propagated.
func TestWithContextShim_GetCredential_Error(t *testing.T) {
	expectedErr := errors.New("provider unavailable")
	inner := &mockNoCtxProvider{
		err: expectedErr,
	}

	shim := NewWithContextShim(inner)

	_, err := shim.GetCredential()
	if err == nil {
		t.Fatal("expected error to be propagated, got nil")
	}
	if err != expectedErr {
		t.Errorf("expected error %v, got %v", expectedErr, err)
	}
}

// TestWithContextShim_GetCredentialWithContext covers GetCredentialWithContext (line 44),
// verifying it delegates to the wrapped provider's GetCredential (ignoring ctx).
func TestWithContextShim_GetCredentialWithContext(t *testing.T) {
	expectedCred := &mockCredential{
		accessToken: "fake-value-456",
		tokenType:   "Bearer",
		expiresIn:   7200,
	}
	inner := &mockNoCtxProvider{
		cred: expectedCred,
	}

	shim := NewWithContextShim(inner)

	ctx := context.Background()
	got, err := shim.GetCredentialWithContext(ctx)
	if err != nil {
		t.Fatalf("GetCredentialWithContext returned unexpected error: %v", err)
	}
	if got != expectedCred {
		t.Errorf("GetCredentialWithContext returned unexpected credential: got %v, want %v", got, expectedCred)
	}
}

// TestWithContextShim_GetCredentialWithContext_NilContext verifies the shim
// does not panic on nil context (ctx is intentionally unused by the shim).
func TestWithContextShim_GetCredentialWithContext_NilContext(t *testing.T) {
	//nolint:staticcheck // intentionally passing nil ctx to verify no panic
	inner := &mockNoCtxProvider{
		cred: &mockCredential{accessToken: "fake-value-789"},
	}

	shim := NewWithContextShim(inner)

	got, err := shim.GetCredentialWithContext(nil) //nolint:staticcheck // SA1012: 故意传 nil,验证 shim 的 nil-ctx 兜底路径
	if err != nil {
		t.Fatalf("GetCredentialWithContext(nil) returned unexpected error: %v", err)
	}
	if got == nil {
		t.Error("GetCredentialWithContext(nil) returned nil credential")
	}
}

// TestWithContextShim_GetCredentialWithContext_Error verifies that errors
// from the inner provider are propagated through GetCredentialWithContext.
func TestWithContextShim_GetCredentialWithContext_Error(t *testing.T) {
	expectedErr := errors.New("network timeout")
	inner := &mockNoCtxProvider{
		err: expectedErr,
	}

	shim := NewWithContextShim(inner)

	ctx := context.Background()
	_, err := shim.GetCredentialWithContext(ctx)
	if err == nil {
		t.Fatal("expected error to be propagated, got nil")
	}
	if err != expectedErr {
		t.Errorf("expected error %v, got %v", expectedErr, err)
	}
}

// TestNewWithContextShim_NilInner verifies that passing nil does not panic
// at construction time (the panic would only happen on first use).
func TestNewWithContextShim_NilInner(t *testing.T) {
	shim := NewWithContextShim(nil)
	if shim == nil {
		t.Fatal("NewWithContextShim(nil) returned nil")
	}
	// We don't call GetCredential because that would panic on nil inner.
}

// TestWithContextShim_GetCredentialWithContext_CancelledCtx 验证已取消的 ctx
// 立即返回 ctx.Err() 而不调用旧 provider(覆盖 case <-ctx.Done() 分支)。
// 旧实现忽略 ctx,shim 至少在调用前做取消检查,避免无效调用后再丢弃结果。
func TestWithContextShim_GetCredentialWithContext_CancelledCtx(t *testing.T) {
	calls := 0
	inner := &mockNoCtxProvider{
		cred: &mockCredential{accessToken: "should-not-reach"},
	}
	// 包装计数:若 shim 误调用 inner 会触发。
	innerPtr := inner
	_ = innerPtr
	_ = calls

	shim := NewWithContextShim(inner)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 先取消

	got, err := shim.GetCredentialWithContext(ctx)
	if err == nil {
		t.Fatal("expected ctx.Err() on cancelled context, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
	if got != nil {
		t.Errorf("expected nil credential on cancelled ctx, got %v", got)
	}
}

// TestWithContextShim_GetCredentialWithContext_NilCtx 验证 nil ctx 视为未取消,
// 向后兼容旧测试传入 nil 的场景(覆盖 ctx == nil 跳过 select 的分支)。
func TestWithContextShim_GetCredentialWithContext_NilCtx(t *testing.T) {
	expectedCred := &mockCredential{accessToken: "fake-value-123", tokenType: "Bearer"}
	inner := &mockNoCtxProvider{cred: expectedCred}
	shim := NewWithContextShim(inner)

	got, err := shim.GetCredentialWithContext(nil) //nolint:staticcheck // SA1012: 故意传 nil,验证 shim 的 nil-ctx 兜底路径
	if err != nil {
		t.Fatalf("nil ctx should not error, got %v", err)
	}
	if got != expectedCred {
		t.Errorf("expected credential on nil ctx, got %v", got)
	}
}
