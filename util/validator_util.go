package util

import "errors"

// ValidateNotBlank 验证字符串非空白
func ValidateNotBlank(value string, fieldName string) error {
	if value == "" {
		return errors.New(fieldName + " cannot be blank")
	}
	return nil
}

// ValidateLocalToken 验证本地令牌
func ValidateLocalToken(token string) error {
	if token == "" {
		return errors.New("local token cannot be empty")
	}
	return nil
}
