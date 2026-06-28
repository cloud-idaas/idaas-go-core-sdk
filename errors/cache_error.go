package errors

import "fmt"

// CacheError 缓存错误 (缓存/刷新失败) (§3.7.6)
type CacheError struct {
	Code    string
	Message string
	Cause   error
}

func (e *CacheError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

func (e *CacheError) ErrorCode() string {
	return e.Code
}

func (e *CacheError) ErrorMessage() string {
	return e.Message
}

// Unwrap 支持 errors.Is / errors.As 链
func (e *CacheError) Unwrap() error {
	return e.Cause
}

// NewCacheError 创建 CacheError
func NewCacheError(code, message string, cause error) *CacheError {
	return &CacheError{
		Code:    code,
		Message: message,
		Cause:   cause,
	}
}
