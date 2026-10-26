package errors

import "fmt"

// CacheError 缓存错误 (缓存/刷新失败)
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

// RequestId 返回服务端请求 ID。
//
// 缓存错误自身不产生 requestId,但它常常包着一次失败的刷新请求;
// 沿 Cause 链向下查找,调用方在最外层就能拿到真正那次 HTTP 请求的 ID。
func (e *CacheError) RequestId() string {
	return requestIdFromChain(e.Cause)
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
