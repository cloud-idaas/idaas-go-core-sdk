package errors

// ConcurrentOperationError 并发操作错误 (extends ClientError) (§3.7.5)
type ConcurrentOperationError struct {
	ClientError
}

// NewConcurrentOperationError 创建 ConcurrentOperationError
func NewConcurrentOperationError(message string, cause error) *ConcurrentOperationError {
	return &ConcurrentOperationError{
		ClientError: ClientError{
			Code:    "ConcurrentOperationFailed",
			Message: message,
			Cause:   cause,
		},
	}
}
