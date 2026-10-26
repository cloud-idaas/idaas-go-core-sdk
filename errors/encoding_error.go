package errors

import "fmt"

// EncodingError 编解码失败
type EncodingError struct {
	Code    string
	Message string
	Cause   error

	// requestId 服务端请求 ID,理由见 ClientError.requestId。
	//
	// 编解码错误本身是本地错误,但"解析服务端响应失败"是它最主要的来源,
	// 而那恰恰是最需要 requestId 去跟服务端对账的场景,因此保留此字段。
	requestId string
}

func (e *EncodingError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

func (e *EncodingError) ErrorCode() string {
	return e.Code
}

func (e *EncodingError) ErrorMessage() string {
	return e.Message
}

// RequestId 返回服务端请求 ID;本层没有时沿 Cause 链向下查找。
func (e *EncodingError) RequestId() string {
	if e.requestId != "" {
		return e.requestId
	}
	return requestIdFromChain(e.Cause)
}

// WithRequestId 写入服务端请求 ID 并返回自身,便于链式构造。
func (e *EncodingError) WithRequestId(requestId string) *EncodingError {
	e.requestId = requestId
	return e
}

// Unwrap 支持 errors.Is / errors.As 链
func (e *EncodingError) Unwrap() error {
	return e.Cause
}

// NewEncodingError 创建 EncodingError
func NewEncodingError(code, message string, cause error) *EncodingError {
	return &EncodingError{
		Code:    code,
		Message: message,
		Cause:   cause,
	}
}
