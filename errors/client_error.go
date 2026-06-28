package errors

import "fmt"

// ClientError 客户端错误 (4xx + 连接失败 + 重定向) (§3.7.2)
type ClientError struct {
	Code    string
	Message string
	Cause   error
}

func (e *ClientError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

func (e *ClientError) ErrorCode() string {
	return e.Code
}

func (e *ClientError) ErrorMessage() string {
	return e.Message
}

// Unwrap 支持 errors.Is / errors.As 链
func (e *ClientError) Unwrap() error {
	return e.Cause
}

// NewClientError 创建 ClientError
func NewClientError(code, message string, cause error) *ClientError {
	return &ClientError{
		Code:    code,
		Message: message,
		Cause:   cause,
	}
}
