package errors

import "fmt"

// ServerError 服务器错误 (5xx + 读超时) (§3.7.3)
type ServerError struct {
	Code       string
	Message    string
	StatusCode int
	Cause      error
}

func (e *ServerError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("[%s] %s (HTTP %d): %v", e.Code, e.Message, e.StatusCode, e.Cause)
	}
	return fmt.Sprintf("[%s] %s (HTTP %d)", e.Code, e.Message, e.StatusCode)
}

func (e *ServerError) ErrorCode() string {
	return e.Code
}

func (e *ServerError) ErrorMessage() string {
	return e.Message
}

// Unwrap 支持 errors.Is / errors.As 链
func (e *ServerError) Unwrap() error {
	return e.Cause
}

// NewServerError 创建 ServerError
func NewServerError(code, message string, statusCode int, cause error) *ServerError {
	return &ServerError{
		Code:       code,
		Message:    message,
		StatusCode: statusCode,
		Cause:      cause,
	}
}
