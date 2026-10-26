package errors

import "github.com/cloud-idaas/idaas-go-core-sdk/constants"

// ConcurrentOperationError 并发操作错误 (extends ClientError)
type ConcurrentOperationError struct {
	ClientError
}

// NewConcurrentOperationError 创建 ConcurrentOperationError
func NewConcurrentOperationError(message string, cause error) *ConcurrentOperationError {
	return &ConcurrentOperationError{
		ClientError: ClientError{
			Code:    constants.ConcurrentOperationFailed,
			Message: message,
			Cause:   cause,
		},
	}
}
