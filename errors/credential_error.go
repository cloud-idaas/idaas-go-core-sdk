package errors

import "fmt"

// CredentialError 凭证操作失败
type CredentialError struct {
	Code    string
	Message string
	Cause   error

	// requestId 服务端请求 ID,理由见 ClientError.requestId。
	//
	// 凭证错误本身是本地错误(如 access_token 缺失),但"服务端返回了
	// 不合规的 token 响应"正是最需要 requestId 去跟服务端对账的场景,
	// 因此保留此字段,由调用方通过 WithRequestId 注入。
	requestId string
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

// RequestId 返回服务端请求 ID。
//
// 凭证错误绝大多数是"换取 token 的那次请求失败了"的包装层,
// 真正的 requestId 在被包的 HttpError / OAuth2Error 上,沿 Cause 链取。
func (e *CredentialError) RequestId() string {
	if e.requestId != "" {
		return e.requestId
	}
	return requestIdFromChain(e.Cause)
}

// WithRequestId 写入服务端请求 ID 并返回自身,便于链式构造。
func (e *CredentialError) WithRequestId(requestId string) *CredentialError {
	e.requestId = requestId
	return e
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
