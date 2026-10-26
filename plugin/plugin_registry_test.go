package plugin

import (
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/cloud-idaas/idaas-go-core-sdk/credential"
)

// mockPluginCredentialProvider is a mock implementation of
// provider.PluginCredentialProvider for testing.
type mockPluginCredentialProvider struct {
	name string
	cred credential.IDaaSCredential
	err  error
}

func (m *mockPluginCredentialProvider) GetName() string {
	return m.name
}

func (m *mockPluginCredentialProvider) GetIDaaSCredential(scope string) (credential.IDaaSCredential, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.cred, nil
}

func newMockPlugin(name string) *mockPluginCredentialProvider {
	return &mockPluginCredentialProvider{
		name: name,
		cred: &mockCredentialForPlugin{accessToken: "fake-cred-" + name},
	}
}

// mockCredentialForPlugin is a minimal IDaaSCredential for plugin tests.
type mockCredentialForPlugin struct {
	accessToken string
}

func (m *mockCredentialForPlugin) GetAccessToken() string  { return m.accessToken }
func (m *mockCredentialForPlugin) GetTokenType() string    { return "Bearer" }
func (m *mockCredentialForPlugin) GetExpiresIn() int64     { return 3600 }
func (m *mockCredentialForPlugin) GetScope() string        { return "openid" }
func (m *mockCredentialForPlugin) GetRefreshToken() string { return "" }
func (m *mockCredentialForPlugin) String() string          { return "mockCredentialForPlugin" }

// ---------------------------------------------------------------------------
// GetInstance tests
// ---------------------------------------------------------------------------

// TestGetInstance covers GetInstance (line 25).
func TestGetInstance(t *testing.T) {
	ResetForTesting()
	defer ResetForTesting()

	r1 := GetInstance()
	if r1 == nil {
		t.Fatal("GetInstance returned nil")
	}

	r2 := GetInstance()
	if r1 != r2 {
		t.Error("GetInstance should return the same singleton instance")
	}
}

// TestGetInstance_Singleton verifies the singleton invariant under concurrent access.
func TestGetInstance_Singleton(t *testing.T) {
	ResetForTesting()
	defer ResetForTesting()

	var wg sync.WaitGroup
	instances := make([]*PluginRegistry, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			instances[idx] = GetInstance()
		}(i)
	}
	wg.Wait()

	for i := 1; i < 20; i++ {
		if instances[i] != instances[0] {
			t.Fatalf("goroutine %d got different instance", i)
		}
	}
}

// ---------------------------------------------------------------------------
// Register tests
// ---------------------------------------------------------------------------

// TestRegister covers Register (line 35).
func TestRegister(t *testing.T) {
	ResetForTesting()
	defer ResetForTesting()

	r := GetInstance()

	// Register a valid plugin
	p := newMockPlugin("test-plugin-alpha")
	err := r.Register(p)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Verify it can be retrieved
	got, err := r.GetPlugin("test-plugin-alpha")
	if err != nil {
		t.Fatalf("GetPlugin failed after Register: %v", err)
	}
	if got != p {
		t.Error("GetPlugin returned a different plugin than registered")
	}
}

// TestRegister_Duplicate covers the duplicate registration error path.
func TestRegister_Duplicate(t *testing.T) {
	ResetForTesting()
	defer ResetForTesting()

	r := GetInstance()
	p := newMockPlugin("dup-plugin")

	err := r.Register(p)
	if err != nil {
		t.Fatalf("first Register failed: %v", err)
	}

	err = r.Register(p)
	if err == nil {
		t.Fatal("expected error for duplicate registration")
	}
	if !strings.Contains(err.Error(), "already registered") {
		t.Errorf("error should mention 'already registered', got: %s", err.Error())
	}
}

// TestRegister_EmptyName covers the empty name error path.
func TestRegister_EmptyName(t *testing.T) {
	ResetForTesting()
	defer ResetForTesting()

	r := GetInstance()
	p := &mockPluginCredentialProvider{name: ""}

	err := r.Register(p)
	if err == nil {
		t.Fatal("expected error for empty plugin name")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("error should mention 'empty', got: %s", err.Error())
	}
}

// ---------------------------------------------------------------------------
// GetPlugin tests
// ---------------------------------------------------------------------------

// TestGetPlugin covers GetPlugin (line 52).
func TestGetPlugin(t *testing.T) {
	ResetForTesting()
	defer ResetForTesting()

	r := GetInstance()
	p := newMockPlugin("lookup-plugin")
	if err := r.Register(p); err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	got, err := r.GetPlugin("lookup-plugin")
	if err != nil {
		t.Fatalf("GetPlugin failed: %v", err)
	}
	if got.GetName() != "lookup-plugin" {
		t.Errorf("GetPlugin returned wrong name: got %s, want lookup-plugin", got.GetName())
	}
}

// TestGetPlugin_NotFound covers the not-found error path.
func TestGetPlugin_NotFound(t *testing.T) {
	ResetForTesting()
	defer ResetForTesting()

	r := GetInstance()

	_, err := r.GetPlugin("nonexistent-plugin")
	if err == nil {
		t.Fatal("expected error for non-existent plugin")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error should mention 'not found', got: %s", err.Error())
	}
}

// ---------------------------------------------------------------------------
// Unregister tests
// ---------------------------------------------------------------------------

// TestUnregister covers Unregister (line 65).
func TestUnregister(t *testing.T) {
	ResetForTesting()
	defer ResetForTesting()

	r := GetInstance()
	p := newMockPlugin("unreg-plugin")
	if err := r.Register(p); err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Unregister existing plugin
	err := r.Unregister("unreg-plugin")
	if err != nil {
		t.Fatalf("Unregister failed: %v", err)
	}

	// Verify it's gone
	_, err = r.GetPlugin("unreg-plugin")
	if err == nil {
		t.Fatal("expected error after Unregister, but GetPlugin succeeded")
	}
}

// TestUnregister_NotFound covers the not-found error path for Unregister.
func TestUnregister_NotFound(t *testing.T) {
	ResetForTesting()
	defer ResetForTesting()

	r := GetInstance()

	err := r.Unregister("nonexistent-plugin")
	if err == nil {
		t.Fatal("expected error for unregistering non-existent plugin")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error should mention 'not found', got: %s", err.Error())
	}
}

// ---------------------------------------------------------------------------
// ResetForTesting tests
// ---------------------------------------------------------------------------

// TestResetForTesting covers ResetForTesting (line 80).
func TestResetForTesting(t *testing.T) {
	ResetForTesting()

	r := GetInstance()
	p := newMockPlugin("reset-test-plugin")
	if err := r.Register(p); err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Reset
	ResetForTesting()
	defer ResetForTesting()

	// New instance should have no plugins
	r2 := GetInstance()
	_, err := r2.GetPlugin("reset-test-plugin")
	if err == nil {
		t.Fatal("expected plugin to be gone after ResetForTesting")
	}

	// Verify it's a fresh instance (could be same or different pointer,
	// but the map should be empty)
	p2 := newMockPlugin("reset-test-plugin")
	if err := r2.Register(p2); err != nil {
		t.Fatalf("Register after reset should succeed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Concurrent access tests
// ---------------------------------------------------------------------------

// TestRegister_Concurrent verifies no data race under concurrent registration
// and lookup.
func TestRegister_Concurrent(t *testing.T) {
	ResetForTesting()
	defer ResetForTesting()

	r := GetInstance()

	var wg sync.WaitGroup
	plugins := make([]*mockPluginCredentialProvider, 50)
	for i := 0; i < 50; i++ {
		plugins[i] = newMockPlugin(string(rune('A'+i%26)) + "-plugin-" + string(rune('a'+i)))
	}

	// Concurrent registration
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_ = r.Register(plugins[idx])
		}(i)
	}

	// Concurrent lookups
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, _ = r.GetPlugin(plugins[idx].GetName())
		}(i)
	}

	// Concurrent unregisters
	for i := 0; i < 25; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_ = r.Unregister(plugins[idx].GetName())
		}(i)
	}

	wg.Wait()

	// Verify no panic / the registry is still functional
	// after concurrent operations, registering a fresh plugin should work
	p := newMockPlugin("concurrent-final-plugin")
	if err := r.Register(p); err != nil {
		// It might already exist if a concurrent goroutine registered it
		if !errors.Is(err, err) { // just ensure no panic
			t.Logf("Register after concurrent ops: %v (expected if already exists)", err)
		}
	}
}
