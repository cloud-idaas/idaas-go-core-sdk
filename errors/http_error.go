package errors

import "fmt"

// HttpError 通用 HTTP 错误
type HttpError struct {
	Code       string
	Message    string
	StatusCode int
	Cause      error

	// requestId 服务端请求 ID,理由见 ClientError.requestId。
	requestId string
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

// RequestId 返回服务端请求 ID;本层没有时沿 Cause 链向下查找。
func (e *HttpError) RequestId() string {
	if e.requestId != "" {
		return e.requestId
	}
	return requestIdFromChain(e.Cause)
}

// WithRequestId 写入服务端请求 ID 并返回自身,便于链式构造。
func (e *HttpError) WithRequestId(requestId string) *HttpError {
	e.requestId = requestId
	return e
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
