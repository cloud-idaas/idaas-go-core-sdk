package util

import (
	"os"
	"path/filepath"
	"strings"
)

// ReadFile 读取文件内容，支持 ~ 路径展开
func ReadFile(filePath string) ([]byte, error) {
	// 展开 ~ 路径
	if strings.HasPrefix(filePath, "~/") {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		filePath = filepath.Join(homeDir, filePath[2:])
	}

	return os.ReadFile(filePath)
}

// WriteFile 写入文件内容。
//
// 默认使用 0600（rw-------）权限，这是 SDK 持久化敏感数据（refresh_token、
// access_token 等长寿命凭证）的安全默认值。多用户机器上 0644 会让同机器
// 任意账号读到凭证，存在严重信息泄露风险。
//
// 如需自定义权限（例如写非敏感缓存），使用 WriteFileMode。
func WriteFile(filePath string, data []byte) error {
	return WriteFileMode(filePath, data, 0600)
}

// WriteFileMode 以指定权限写入文件内容。
func WriteFileMode(filePath string, data []byte, mode os.FileMode) error {
	return os.WriteFile(filePath, data, mode)
}
