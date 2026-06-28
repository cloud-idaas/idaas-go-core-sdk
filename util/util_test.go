package util

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateNotBlank(t *testing.T) {
	// Test valid input
	err := ValidateNotBlank("test", "field")
	if err != nil {
		t.Errorf("Expected no error for non-blank value, got: %v", err)
	}

	// Test blank input
	err = ValidateNotBlank("", "field")
	if err == nil {
		t.Error("Expected error for blank value")
	}
}

func TestNormalizeEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"HTTP to HTTPS", "http://example.com", "https://example.com"},
		{"Already HTTPS", "https://example.com", "https://example.com"},
		{"No protocol", "example.com", "example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizeEndpoint(tt.input)
			if result != tt.expected {
				t.Errorf("Expected %s to be normalized to '%s', got '%s'", tt.input, tt.expected, result)
			}
		})
	}
}

func TestExtractUrlOrigin(t *testing.T) {
	successCases := []struct {
		name     string
		input    string
		expected string
	}{
		{"with path", "https://y1t726cn.aliyunidaas.com/api/v2/iauths_system/oauth2", "https://y1t726cn.aliyunidaas.com"},
		{"with port and path", "https://idaas.example.com:8443/api/v2/xxx/oauth2", "https://idaas.example.com:8443"},
		{"origin only", "https://accounts.example.com", "https://accounts.example.com"},
		{"with query and fragment", "https://example.com/x?y=1#z", "https://example.com"},
		{"http scheme retained", "http://example.com/path", "http://example.com"},
		{"trailing slash", "https://example.com/", "https://example.com"},
	}
	for _, tc := range successCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ExtractUrlOrigin(tc.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.expected {
				t.Errorf("input=%s, want %s, got %s", tc.input, tc.expected, got)
			}
		})
	}

	errorCases := []struct {
		name  string
		input string
	}{
		{"empty string", ""},
		{"missing scheme", "example.com/path"},
		{"scheme only", "https://"},
		{"only path", "/api/v2/xxx"},
	}
	for _, tc := range errorCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ExtractUrlOrigin(tc.input)
			if err == nil {
				t.Errorf("expected error for input %q, got nil", tc.input)
			}
		})
	}
}

func TestValidateScope(t *testing.T) {
	// Test valid scope
	err := ValidateScope("api.example.com|read")
	if err != nil {
		t.Errorf("Expected no error for valid scope, got: %v", err)
	}

	// Test valid scope with hyphen (regression test for regex change)
	err = ValidateScope("read-write")
	if err != nil {
		t.Errorf("Expected no error for scope with hyphen, got: %v", err)
	}

	err = ValidateScope("user:profile-read")
	if err != nil {
		t.Errorf("Expected no error for scope with colon and hyphen, got: %v", err)
	}

	// Test empty scope
	err = ValidateScope("")
	if err == nil {
		t.Error("Expected error for empty scope")
	}

	// Test invalid scope with special characters
	err = ValidateScope("api@example.com|read")
	if err == nil {
		t.Error("Expected error for invalid scope")
	}
}

func TestExtractAudienceFromScope(t *testing.T) {
	// Test valid audience extraction
	audience, err := ExtractAudienceFromScope("audience:api.example.com read:file")
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if audience != "api.example.com" {
		t.Errorf("Expected audience to be 'api.example.com', got '%s'", audience)
	}

	// Test no audience in scope
	_, err = ExtractAudienceFromScope("read:file write:file")
	if err == nil {
		t.Error("Expected error when no audience found")
	}
}

func TestReadFile(t *testing.T) {
	// Create a temporary file for testing
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.txt")
	content := []byte("test content")

	err := os.WriteFile(tmpFile, content, 0644)
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	// Test reading the file
	readContent, err := ReadFile(tmpFile)
	if err != nil {
		t.Errorf("Expected no error reading file, got: %v", err)
	}

	if string(readContent) != string(content) {
		t.Errorf("Expected content '%s', got '%s'", string(content), string(readContent))
	}

	// Test reading non-existent file
	_, err = ReadFile("/non/existent/file.txt")
	if err == nil {
		t.Error("Expected error for non-existent file")
	}
}

func TestReadFileWithTilde(t *testing.T) {
	// Test tilde expansion
	homeDir, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("Failed to get home directory: %v", err)
	}
	tmpFile := filepath.Join(homeDir, "test_tilde.txt")
	content := []byte("tilde test content")

	err = os.WriteFile(tmpFile, content, 0644)
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile)

	// Test reading with tilde path
	tildePath := "~/test_tilde.txt"
	readContent, err := ReadFile(tildePath)
	if err != nil {
		t.Errorf("Expected no error reading file with tilde, got: %v", err)
	}

	if string(readContent) != string(content) {
		t.Errorf("Expected content '%s', got '%s'", string(content), string(readContent))
	}
}

func TestWriteFile(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "write_test.txt")
	content := []byte("write test content")

	err := WriteFile(tmpFile, content)
	if err != nil {
		t.Errorf("Expected no error writing file, got: %v", err)
	}

	// Verify content was written
	readContent, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Errorf("Expected no error reading written file, got: %v", err)
	}

	if string(readContent) != string(content) {
		t.Errorf("Expected written content '%s', got '%s'", string(content), string(readContent))
	}
}
