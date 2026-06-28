package errors

// IDaaSError 基础接口 (§3.7)
// 所有 SDK 错误都必须实现此接口
type IDaaSError interface {
	error
	ErrorCode() string
	ErrorMessage() string
}
