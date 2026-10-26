package errors

import (
	"fmt"

	"github.com/cloud-idaas/idaas-go-core-sdk/constants"
)

// IDaaSUnexpectedError 意外/内部错误
type IDaaSUnexpectedError struct {
	Message string
	Cause   error
}

func (e *IDaaSUnexpectedError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("[%s] %s: %v", constants.UnexpectedError, e.Message, e.Cause)
	}
	return fmt.Sprintf("[%s] %s", constants.UnexpectedError, e.Message)
}

func (e *IDaaSUnexpectedError) ErrorCode() string {
	return constants.UnexpectedError
}

func (e *IDaaSUnexpectedError) ErrorMessage() string {
	return e.Message
}

// RequestId 返回服务端请求 ID;自身没有,沿 Cause 链向下查找。
func (e *IDaaSUnexpectedError) RequestId() string {
	return requestIdFromChain(e.Cause)
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
