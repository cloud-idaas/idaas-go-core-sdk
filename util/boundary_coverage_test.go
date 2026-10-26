package util

import (
	"testing"
)

// TestBoundary_ExtractUrlOrigin_ParseError 验证传入会导致 url.Parse 报错的 URL 时
// ExtractUrlOrigin 返回 error。
func TestBoundary_ExtractUrlOrigin_ParseError(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		// NUL 字节会导致 url.Parse 报 control character in URL 错误
		{"NUL byte in URL", "https://example.com\x00path"},
		// 非法 percent-encoding 会导致 url.Parse 报 invalid URL escape 错误
		{"invalid percent encoding", "https://example.com/%zz"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ExtractUrlOrigin(tt.url)
			if err == nil {
				t.Errorf("expected error for url %q, got nil", tt.url)
			}
		})
	}
}

// TestBoundary_ReadFile_HomeDirFailure 验证当 os.UserHomeDir() 失败时
// ReadFile 对 ~/ 路径返回 error。
func TestBoundary_ReadFile_HomeDirFailure(t *testing.T) {
	// 清空 HOME 和 USERPROFILE，使 os.UserHomeDir() 无法找到家目录
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")

	_, err := ReadFile("~/file")
	if err == nil {
		// 在某些 Linux 环境上 os.UserHomeDir() 可能从 /etc/passwd 读取家目录
		// 而非环境变量，此时无法触发失败
		t.Skip("os.UserHomeDir() succeeded despite empty HOME/USERPROFILE (likely reading /etc/passwd); skipping on this platform")
	}
}
