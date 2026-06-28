package errors

import "fmt"

// EncodingError 编解码失败 (§3.7.8)
type EncodingError struct {
	Code    string
	Message string
	Cause   error
}

func (e *EncodingError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

func (e *EncodingError) ErrorCode() string {
	return e.Code
}

func (e *EncodingError) ErrorMessage() string {
	return e.Message
}

// Unwrap 支持 errors.Is / errors.As 链
func (e *EncodingError) Unwrap() error {
	return e.Cause
}

// NewEncodingError 创建 EncodingError
func NewEncodingError(code, message string, cause error) *EncodingError {
	return &EncodingError{
		Code:    code,
		Message: message,
		Cause:   cause,
	}
}
