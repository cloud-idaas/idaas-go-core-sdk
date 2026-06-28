package errors

import "fmt"

// CredentialError 凭证操作失败 (§3.7.7)
type CredentialError struct {
	Code    string
	Message string
	Cause   error
}

func (e *CredentialError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

func (e *CredentialError) ErrorCode() string {
	return e.Code
}

func (e *CredentialError) ErrorMessage() string {
	return e.Message
}

// Unwrap 支持 errors.Is / errors.As 链
func (e *CredentialError) Unwrap() error {
	return e.Cause
}

// NewCredentialError 创建 CredentialError
func NewCredentialError(code, message string, cause error) *CredentialError {
	return &CredentialError{
		Code:    code,
		Message: message,
		Cause:   cause,
	}
}
