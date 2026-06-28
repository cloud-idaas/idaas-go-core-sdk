package errors

import "fmt"

// HttpError 通用 HTTP 错误 (§3.7.9)
type HttpError struct {
	Code       string
	Message    string
	StatusCode int
	Cause      error
}

func (e *HttpError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("[%s] %s (HTTP %d): %v", e.Code, e.Message, e.StatusCode, e.Cause)
	}
	return fmt.Sprintf("[%s] %s (HTTP %d)", e.Code, e.Message, e.StatusCode)
}

func (e *HttpError) ErrorCode() string {
	return e.Code
}

func (e *HttpError) ErrorMessage() string {
	return e.Message
}

// Unwrap 支持 errors.Is / errors.As 链
func (e *HttpError) Unwrap() error {
	return e.Cause
}

// NewHttpError 创建 HttpError
func NewHttpError(code, message string, statusCode int, cause error) *HttpError {
	return &HttpError{
		Code:       code,
		Message:    message,
		StatusCode: statusCode,
		Cause:      cause,
	}
}
