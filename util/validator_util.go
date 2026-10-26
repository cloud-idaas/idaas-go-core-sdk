package util

import (
	"errors"
	"strings"
)

// ValidateNotBlank 验证字符串非空白。
//
// 用 strings.TrimSpace 判定,拦截纯空白值(" "/"\t\n" 等)绕过 == "" 检查
// 的配置(否则空白 clientId/instanceId 通过校验进入运行时,IdP 返回 401
// 调用方无从定位为配置问题)。一处覆盖所有调用点。
func ValidateNotBlank(value, fieldName string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New(fieldName + " cannot be blank")
	}
	return nil
}

// ValidateLocalToken 验证本地令牌
func ValidateLocalToken(token string) error {
	if strings.TrimSpace(token) == "" {
		return errors.New("local token cannot be empty")
	}
	return nil
}
