package errors

import "fmt"

// ServerError 服务器错误 (5xx + 读超时)
type ServerError struct {
	Code       string
	Message    string
	StatusCode int
	Cause      error

	// requestId 服务端请求 ID,理由见 ClientError.requestId。
	requestId string
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

// RequestId 返回服务端请求 ID;本层没有时沿 Cause 链向下查找。
//
// 5xx 场景下这是最有价值的一个字段:客户端除了重试别无他法,
// 真正能推动问题解决的是把 requestId 交给服务端。
func (e *ServerError) RequestId() string {
	if e.requestId != "" {
		return e.requestId
	}
	return requestIdFromChain(e.Cause)
}

// WithRequestId 写入服务端请求 ID 并返回自身,便于链式构造。
func (e *ServerError) WithRequestId(requestId string) *ServerError {
	e.requestId = requestId
	return e
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
