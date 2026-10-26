package errors

import "fmt"

// ClientError 客户端错误 (4xx + 连接失败 + 重定向)
type ClientError struct {
	Code    string
	Message string
	Cause   error

	// requestId 服务端请求 ID。
	//
	// 刻意用非导出字段 + RequestId() 方法而不是导出字段:
	// Go 不允许同名的字段与方法共存,而 IDaaSError 接口要求 RequestId() 方法,
	// 导出字段只能改叫 RequestID——与方法名仅差一个字母,是比不可写更糟的坑。
	// SDK 内部用 WithRequestId 写入。
	requestId string
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

// RequestId 返回服务端请求 ID;本层没有时沿 Cause 链向下查找。
func (e *ClientError) RequestId() string {
	if e.requestId != "" {
		return e.requestId
	}
	return requestIdFromChain(e.Cause)
}

// WithRequestId 写入服务端请求 ID 并返回自身,便于链式构造:
//
//	return errors.NewClientError(code, msg, nil).WithRequestId(resp.RequestId())
//
// 对应 Java 的 ClientException#setRequestId。
//
// ⚠️ 对于内嵌 ClientError 的 ConfigError / ConcurrentOperationError,
// 本方法返回的是 *ClientError 而非外层类型,链式写法会丢类型;
// 这两类都是本地错误、不带 requestId,正常不会用到。
func (e *ClientError) WithRequestId(requestId string) *ClientError {
	e.requestId = requestId
	return e
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
