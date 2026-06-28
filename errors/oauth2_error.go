package errors

import "fmt"

// OAuth2Error OAuth2 标准错误响应（RFC 6749 §5.2 / Device Authorization Grant §3.5）
//
// 当 token endpoint / device authorization endpoint 返回 4xx 时，body 通常是：
//
//	{ "error": "invalid_grant", "error_description": "...", "error_uri": "..." }
//
// 此错误类型保留原始 HTTP 状态码与 OAuth2 标准字段，供调用方用 errors.As 解构后
// 按 OAuthCode 做行为分支（例如 device flow 区分 authorization_pending / slow_down /
// access_denied / expired_token）。
type OAuth2Error struct {
	HTTPStatus       int    // HTTP 状态码（如 400 / 401）
	OAuthCode        string `json:"error"`             // 标准 error 字段
	OAuthDescription string `json:"error_description"` // 标准 error_description 字段
	OAuthURI         string `json:"error_uri"`         // 标准 error_uri 字段
	RawBody          string // 原始响应体（兜底，便于排查非标响应）
	Cause            error
}

// Error 返回人类可读的错误信息（不包含 RawBody，避免敏感信息泄露或日志过长）
func (e *OAuth2Error) Error() string {
	base := fmt.Sprintf("[OAuth2 %s] (HTTP %d)", e.OAuthCode, e.HTTPStatus)
	if e.OAuthDescription != "" {
		base += ": " + e.OAuthDescription
	}
	return base
}

// ErrorCode 实现 IDaaSError 接口
func (e *OAuth2Error) ErrorCode() string {
	if e.OAuthCode != "" {
		return e.OAuthCode
	}
	return "OAuth2Error"
}

// ErrorMessage 实现 IDaaSError 接口
func (e *OAuth2Error) ErrorMessage() string {
	if e.OAuthDescription != "" {
		return e.OAuthDescription
	}
	return e.RawBody
}

// Unwrap 支持 errors.Is / errors.As 链
func (e *OAuth2Error) Unwrap() error {
	return e.Cause
}

// NewOAuth2Error 创建 OAuth2Error
func NewOAuth2Error(httpStatus int, oauthCode, oauthDescription, rawBody string, cause error) *OAuth2Error {
	return &OAuth2Error{
		HTTPStatus:       httpStatus,
		OAuthCode:        oauthCode,
		OAuthDescription: oauthDescription,
		RawBody:          rawBody,
		Cause:            cause,
	}
}
