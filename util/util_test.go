package util

import (
	"bytes"
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

	// 纯空白值(" "/"\t\n") 必须被拦截,否则配置通过校验进运行时致 IdP 401 无从定位。
	for _, bad := range []string{" ", "\t", "\n", "\t\n ", "  \r\n  "} {
		if err := ValidateNotBlank(bad, "field"); err == nil {
			t.Errorf("ValidateNotBlank(%q) should reject whitespace-only value", bad)
		}
	}

	// 内部含空格的非空白值仍然合法(不误伤合法值)。
	if err := ValidateNotBlank("a b", "field"); err != nil {
		t.Errorf("ValidateNotBlank(\"a b\") should pass, got %v", err)
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
		// 裸 host 自动补全 https:// —— 与 Java NormalizeUtil.convertHttps /
		// Python NormalizeUtil._convert_to_https 对齐（POP 端点惯例形态）。
		{"No protocol", "example.com", "https://example.com"},
		{"Bare host with port", "eiam.cn-hangzhou.aliyuncs.com:443", "https://eiam.cn-hangzhou.aliyuncs.com:443"},
		{"Bare host with path", "example.com/api/v2", "https://example.com/api/v2"},
		{"Empty stays empty", "", ""},
		{"Whitespace trimmed", "  example.com  ", "https://example.com"},
		{"Illegal scheme untouched", "ftp://example.com", "ftp://example.com"},
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
		{"with path", "https://your-instance.example.com/api/v2/iauths_system/oauth2", "https://your-instance.example.com"},
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

func TestReadFile(t *testing.T) {
	// Create a temporary file for testing
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.txt")
	content := []byte("test content")

	err := os.WriteFile(tmpFile, content, 0o644)
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	// Test reading the file
	readContent, err := ReadFile(tmpFile)
	if err != nil {
		t.Errorf("Expected no error reading file, got: %v", err)
	}

	if !bytes.Equal(readContent, content) {
		t.Errorf("Expected content '%s', got '%s'", string(content), string(readContent))
	}

	// Test reading non-existent file
	_, err = ReadFile("/non/existent/file.txt")
	if err == nil {
		t.Error("Expected error for non-existent file")
	}
}

func TestReadFileWithTilde(t *testing.T) {
	// 用临时目录冒充家目录：既不往真实 $HOME 落文件，也兼容 HOME 只读的 CI runner。
	// os.UserHomeDir() 在 macOS/Linux 取 $HOME、Windows 取 %USERPROFILE%，两个都设上。
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	t.Setenv("USERPROFILE", homeDir)

	content := []byte("tilde test content")
	tmpFile := filepath.Join(homeDir, "test_tilde.txt")
	if err := os.WriteFile(tmpFile, content, 0o600); err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	// Test reading with tilde path
	tildePath := "~/test_tilde.txt"
	readContent, err := ReadFile(tildePath)
	if err != nil {
		t.Errorf("Expected no error reading file with tilde, got: %v", err)
	}

	if !bytes.Equal(readContent, content) {
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

	if !bytes.Equal(readContent, content) {
		t.Errorf("Expected written content '%s', got '%s'", string(content), string(readContent))
	}
}

// TestWriteFileMode_CreatesWithRequestedPermissions 新文件以请求的权限创建。
func TestWriteFileMode_CreatesWithRequestedPermissions(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "secret.txt")
	content := []byte("secret token")

	if err := WriteFileMode(tmpFile, content, 0o600); err != nil {
		t.Fatalf("WriteFileMode failed: %v", err)
	}

	info, err := os.Stat(tmpFile)
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("file mode = %o, want 0600", perm)
	}

	read, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if !bytes.Equal(read, content) {
		t.Errorf("content = %q, want %q", string(read), string(content))
	}
}

// TestWriteFileMode_TightensExistingPermissions 覆写已存在文件时权限被收紧，无 TOCTOU 窗口。
func TestWriteFileMode_TightensExistingPermissions(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "token.json")

	// 预先以宽松权限创建文件
	if err := os.WriteFile(tmpFile, []byte("old"), 0o644); err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	content := []byte("new secret")
	if err := WriteFileMode(tmpFile, content, 0o600); err != nil {
		t.Fatalf("WriteFileMode failed: %v", err)
	}

	info, err := os.Stat(tmpFile)
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("file mode = %o, want 0600 after overwrite", perm)
	}
}

// TestNormalizeEndpointWithSecurity 覆盖 allowInsecure 逃生舱与补全规则的交叉组合。
func TestNormalizeEndpointWithSecurity(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		allowInsecure bool
		expected      string
	}{
		{"bare host always becomes https even with allowInsecure", "openapi.example.com", true, "https://openapi.example.com"},
		{"bare host without allowInsecure", "openapi.example.com", false, "https://openapi.example.com"},
		{"http kept when allowInsecure", "http://localhost:8080/token", true, "http://localhost:8080/token"},
		{"http upgraded when not allowInsecure", "http://localhost:8080/token", false, "https://localhost:8080/token"},
		// 逃生舱只放行"显式 http://"；裸 host 的补全目标恒为 https，不会被降级成 http。
		{"uppercase scheme still upgraded", "HTTP://Example.COM", false, "https://Example.COM"},
		{"empty with allowInsecure", "", true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizeEndpointWithSecurity(tt.input, tt.allowInsecure); got != tt.expected {
				t.Errorf("NormalizeEndpointWithSecurity(%q, %v) = %q, want %q", tt.input, tt.allowInsecure, got, tt.expected)
			}
		})
	}
}
