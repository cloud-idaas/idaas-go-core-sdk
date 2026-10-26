package credential

import (
	"strings"
	"testing"
)

// TestIDaaSTokenResponse_ValidateLocalToken_Valid covers ValidateLocalToken (line 116)
// with a valid Bearer token response.
func TestIDaaSTokenResponse_ValidateLocalToken_Valid(t *testing.T) {
	resp := &IDaaSTokenResponse{
		AccessToken: "fake-credential-value-001",
		TokenType:   "Bearer",
		ExpiresIn:   3600,
	}
	if err := resp.ValidateLocalToken(); err != nil {
		t.Errorf("expected nil error for valid response, got: %v", err)
	}
}

// TestIDaaSTokenResponse_ValidateLocalToken_ValidCaseInsensitive verifies
// that "bearer" matching is case-insensitive.
func TestIDaaSTokenResponse_ValidateLocalToken_ValidCaseInsensitive(t *testing.T) {
	tests := []struct {
		name      string
		tokenType string
	}{
		{"lowercase", "bearer"},
		{"uppercase", "BEARER"},
		{"mixed", "BeArEr"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &IDaaSTokenResponse{
				AccessToken: "fake-credential-value-001",
				TokenType:   tt.tokenType,
				ExpiresIn:   3600,
			}
			if err := resp.ValidateLocalToken(); err != nil {
				t.Errorf("expected nil error for %s, got: %v", tt.tokenType, err)
			}
		})
	}
}

// TestIDaaSTokenResponse_ValidateLocalToken_EmptyAccessToken verifies
// that an empty access_token triggers AccessTokenNotFound error.
func TestIDaaSTokenResponse_ValidateLocalToken_EmptyAccessToken(t *testing.T) {
	resp := &IDaaSTokenResponse{
		AccessToken: "",
		TokenType:   "Bearer",
	}
	err := resp.ValidateLocalToken()
	if err == nil {
		t.Fatal("expected error for empty access_token")
	}
	if !strings.Contains(err.Error(), "access_token") {
		t.Errorf("error should mention access_token, got: %s", err.Error())
	}
}

// TestIDaaSTokenResponse_ValidateLocalToken_InvalidTokenType verifies
// that a non-Bearer token_type triggers InvalidTokenType error.
func TestIDaaSTokenResponse_ValidateLocalToken_InvalidTokenType(t *testing.T) {
	tests := []struct {
		name      string
		tokenType string
	}{
		{"MAC", "MAC"},
		{"empty", ""},
		{"random", "random_type"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &IDaaSTokenResponse{
				AccessToken: "fake-credential-value-001",
				TokenType:   tt.tokenType,
			}
			err := resp.ValidateLocalToken()
			if err == nil {
				t.Fatalf("expected error for token_type=%s, got nil", tt.tokenType)
			}
			if !strings.Contains(err.Error(), "Bearer") {
				t.Errorf("error should mention Bearer, got: %s", err.Error())
			}
		})
	}
}

// TestIDaaSTokenResponse_String covers String (line 139), verifying that
// the redacted representation does not leak the raw credential.
func TestIDaaSTokenResponse_String(t *testing.T) {
	resp := &IDaaSTokenResponse{
		AccessToken:  "abcdef-long-fake-credential-value-1234567890",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		Scope:        "openid profile",
		RefreshToken: "xyzuvw-long-fake-credential-value-9876543210",
	}

	s := resp.String()

	// Should contain the token type
	if !strings.Contains(s, "Bearer") {
		t.Errorf("String() should contain token type 'Bearer', got: %s", s)
	}

	// Should contain the scope
	if !strings.Contains(s, "openid profile") {
		t.Errorf("String() should contain scope, got: %s", s)
	}

	// Should contain expires_in value
	if !strings.Contains(s, "3600") {
		t.Errorf("String() should contain expires_in, got: %s", s)
	}

	// Must NOT contain raw credentials
	if strings.Contains(s, "abcdef-long-fake-credential-value-1234567890") {
		t.Errorf("String() must not leak raw credential, got: %s", s)
	}

	if strings.Contains(s, "xyzuvw-long-fake-credential-value-9876543210") {
		t.Errorf("String() must not leak raw refresh credential, got: %s", s)
	}

	// Should contain redacted form (prefix + *** marker)
	if !strings.Contains(s, "***") {
		t.Errorf("String() should contain redacted marker '***', got: %s", s)
	}

	// Should have the IDaaSCredential prefix
	if !strings.HasPrefix(s, "IDaaSCredential{") {
		t.Errorf("String() should start with 'IDaaSCredential{', got: %s", s)
	}
}

// TestIDaaSTokenResponse_String_EmptyFields verifies that String() does not
// panic when fields are empty.
func TestIDaaSTokenResponse_String_EmptyFields(t *testing.T) {
	resp := &IDaaSTokenResponse{}

	s := resp.String()
	if s == "" {
		t.Error("String() should not be empty even with zero values")
	}
	if !strings.HasPrefix(s, "IDaaSCredential{") {
		t.Errorf("String() should start with 'IDaaSCredential{', got: %s", s)
	}
}

// TestIDaaSTokenResponse_String_ShortValue verifies String() handles short
// values (shorter than the redact prefix length) without panicking.
func TestIDaaSTokenResponse_String_ShortValue(t *testing.T) {
	resp := &IDaaSTokenResponse{
		AccessToken: "ab",
		TokenType:   "Bearer",
		ExpiresIn:   10,
	}

	s := resp.String()
	// Short values are still redacted with *** marker
	if !strings.Contains(s, "***") {
		t.Errorf("String() should contain redact marker for short value, got: %s", s)
	}
}
