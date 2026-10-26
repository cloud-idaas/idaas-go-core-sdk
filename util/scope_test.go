package util

import (
	"testing"
)

func TestSplitScope(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{"single", "api.example.com|read", []string{"api.example.com|read"}},
		{"unsorted becomes sorted", "api.example.com|write api.example.com|read", []string{"api.example.com|read", "api.example.com|write"}},
		{"extra spaces", "  api.example.com|read   api.example.com|write  ", []string{"api.example.com|read", "api.example.com|write"}},
		{"empty", "", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SplitScope(tt.input)
			if len(got) != len(tt.expected) {
				t.Fatalf("got %v, want %v", got, tt.expected)
			}
			for i := range got {
				if got[i] != tt.expected[i] {
					t.Errorf("[%d] got %q, want %q", i, got[i], tt.expected[i])
				}
			}
		})
	}
}

func TestCanonicalizeScope(t *testing.T) {
	if CanonicalizeScope("b|y a|x") != "a|x b|y" {
		t.Errorf("CanonicalizeScope should sort: got %q", CanonicalizeScope("b|y a|x"))
	}
	if CanonicalizeScope("") != "" {
		t.Errorf("CanonicalizeScope of empty should be empty")
	}
}

func TestIsValidScope(t *testing.T) {
	valid := []string{"api.example.com|read", "aud|scope1", "a.b.c|x.y.z"}
	invalid := []string{"no-pipe", "", "|", "aud|", "|perm", "a|b|c"}
	for _, s := range valid {
		if !IsValidScope(s) {
			t.Errorf("expected IsValidScope(%q)=true", s)
		}
	}
	for _, s := range invalid {
		if IsValidScope(s) {
			t.Errorf("expected IsValidScope(%q)=false", s)
		}
	}
}

func TestValidateScopeM2(t *testing.T) {
	// valid
	if err := ValidateScope("api.example.com|read"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if err := ValidateScope("api.example.com|read api.example.com|write"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	// empty
	if err := ValidateScope(""); err == nil {
		t.Error("expected error for empty scope")
	}
	// invalid format
	if err := ValidateScope("no-pipe"); err == nil {
		t.Error("expected error for invalid scope format")
	}
	// multiple audiences
	if err := ValidateScope("api1.example.com|read api2.example.com|write"); err == nil {
		t.Error("expected error for multiple audiences")
	}
}

func TestExtractAudienceM2(t *testing.T) {
	aud, err := ExtractAudience("api.example.com|read")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if aud != "api.example.com" {
		t.Errorf("got %q, want %q", aud, "api.example.com")
	}
	// no pipe
	_, err = ExtractAudience("no-pipe")
	if err == nil {
		t.Error("expected error for scope without pipe")
	}
}

// BenchmarkCanonicalizeScope measures the scope canonicalization hot path (M2).
//
// CanonicalizeScope runs on every GetIDaaSCredentialProviderByScope lookup to
// build the cache key; keeping it allocation-free matters for high-throughput
// callers that mint providers per request.
func BenchmarkCanonicalizeScope(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = CanonicalizeScope("api://example.com|read api://example.com|write openid offline_access")
	}
}

// BenchmarkCanonicalizeScopeSingle measures the common single-scope case.
func BenchmarkCanonicalizeScopeSingle(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = CanonicalizeScope("api://example.com|read")
	}
}

// BenchmarkValidateScope measures the full validation path (split + pattern + audience uniqueness).
func BenchmarkValidateScope(b *testing.B) {
	scope := "api://example.com|read api://example.com|write openid offline_access"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ValidateScope(scope)
	}
}
