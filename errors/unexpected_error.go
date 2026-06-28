package errors

import "fmt"

// IDaaSUnexpectedError 意外/内部错误 (§3.7.10)
type IDaaSUnexpectedError struct {
	Message string
	Cause   error
}

func (e *IDaaSUnexpectedError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("[UnexpectedError] %s: %v", e.Message, e.Cause)
	}
	return fmt.Sprintf("[UnexpectedError] %s", e.Message)
}

func (e *IDaaSUnexpectedError) ErrorCode() string {
	return "UnexpectedError"
}

func (e *IDaaSUnexpectedError) ErrorMessage() string {
	return e.Message
}

// Unwrap 支持 errors.Is / errors.As 链
func (e *IDaaSUnexpectedError) Unwrap() error {
	return e.Cause
}

// NewUnexpectedError 创建 IDaaSUnexpectedError
func NewUnexpectedError(message string, cause error) *IDaaSUnexpectedError {
	return &IDaaSUnexpectedError{
		Message: message,
		Cause:   cause,
	}
}
