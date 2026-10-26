package errors

import (
	"fmt"
	"regexp"
	"unicode/utf8"

	"github.com/cloud-idaas/idaas-go-core-sdk/constants"
)

// maxErrorDescLen 是 OAuth2Error.Error() / ServerError.Message 中 error_description
// 文本的最大字节长度。服务端的 error_description 可能极长(甚至回显 refresh_token /
// client_secret),原样拼进 err.Error() / 日志会泄露敏感信息或撑爆日志。
// 完整文本仍可通过 ErrorMessage() / OAuthDescription 字段获取(errors.As)。
const maxErrorDescLen = 512

// truncateForLog 把字符串截断为不超过 max 字节,用于构造人类可读的错误消息。
// 与 util.TruncateForError 语义一致,但 errors 包不能 import util(循环依赖)。
func truncateForLog(s string, maxLen int) string {
	if maxLen <= 0 {
		maxLen = maxErrorDescLen
	}
	if len(s) <= maxLen {
		return s
	}
	// 回退到完整 UTF-8 码点边界,避免切断多字节序列产生非法字符串。
	for maxLen > 0 && !utf8.RuneStart(s[maxLen]) {
		maxLen--
	}
	return s[:maxLen] + "...(truncated)"
}

// sensitiveValuePattern 匹配 OAuth2 参数赋值中的敏感值,形如
// refresh_token=xxx / access_token:"xxx" / client_secret: xxx。
// 捕获组 1 = 参数名,组 2 = 分隔符(=/:/空格),组 3 = 值。
// 值截取到下一个分隔符或行尾,避免贪婪匹配吞掉整个 description。
var sensitiveValuePattern = regexp.MustCompile(
	`(?i)(refresh_token|access_token|id_token|client_secret|client_assertion|assertion|code|token|password|secret)(\s*[=:]\s*)([^\s&,"']+)`,
)

// jwtPattern 匹配 JWT token(以 eyJ 开头,base64url 字符),服务端可能在
// error_description 中回显完整 token。
var jwtPattern = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*`)

// RedactDescription 在截断前对 error_description 做内容脱敏。
// 仅按长度截断(512 字节)会让短 refresh_token(< 512 字节)被完整回显在 Error() 中,
// 故先替换已知敏感参数的值和 JWT token 为 ***,再交给 truncateForLog 做长度截断。
// 完整原文仍可通过 FullDescription() 取得。
//
// 导出供 oauth2 包在 5xx 路径复用:ServerError.Message 由调用方拼装,
// 经此脱敏后与 4xx OAuth2Error.Error() 的脱敏口径一致(均先脱敏再截断)。
func RedactDescription(s string) string {
	s = jwtPattern.ReplaceAllString(s, "***")
	s = sensitiveValuePattern.ReplaceAllString(s, "${1}${2}***")
	return s
}

// OAuth2Error OAuth2 标准错误响应（RFC 6749 / Device Authorization Grant）
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

	// requestId 服务端请求 ID,理由见 ClientError.requestId。
	//
	// 非导出还有一个额外好处:本结构体会被 json.Unmarshal 直接填充,
	// 非导出字段不会被响应体里同名的 key 意外覆盖。
	requestId string
}

// Error 返回人类可读的错误信息（不包含 RawBody，避免敏感信息泄露或日志过长）。
//
// OAuthDescription 先经 redactDescription 替换敏感参数值与 JWT token,
// 再截断到 maxErrorDescLen 字节;仅截断会让短 refresh_token(< 512 字节)
// 被完整回显。完整文本通过 FullDescription() 获取。
func (e *OAuth2Error) Error() string {
	base := fmt.Sprintf("[OAuth2 %s] (HTTP %d)", e.OAuthCode, e.HTTPStatus)
	if e.OAuthDescription != "" {
		base += ": " + truncateForLog(RedactDescription(e.OAuthDescription), maxErrorDescLen)
	}
	return base
}

// ErrorCode 实现 IDaaSError 接口
func (e *OAuth2Error) ErrorCode() string {
	if e.OAuthCode != "" {
		return e.OAuthCode
	}
	return constants.OAuth2Failed
}

// ErrorMessage 实现 IDaaSError 接口
func (e *OAuth2Error) ErrorMessage() string {
	if e.OAuthDescription != "" {
		return e.OAuthDescription
	}
	return e.RawBody
}

// FullDescription 返回完整的 error_description,不受 Error() 的截断影响。
// 调用方用 errors.As 拿到 *OAuth2Error 后可取完整文本用于结构化日志/排查,
// 而 Error() 仅用于人类可读的简短消息。
func (e *OAuth2Error) FullDescription() string {
	return e.OAuthDescription
}

// RequestId 返回服务端请求 ID;本层没有时沿 Cause 链向下查找。
//
// OAuth2 协议本身不规定 requestId,它来自 IDaaS 的响应头/响应体扩展字段,
// 由 HTTP 层解析后用 WithRequestId 注入。
func (e *OAuth2Error) RequestId() string {
	if e.requestId != "" {
		return e.requestId
	}
	return requestIdFromChain(e.Cause)
}

// WithRequestId 写入服务端请求 ID 并返回自身,便于链式构造。
func (e *OAuth2Error) WithRequestId(requestId string) *OAuth2Error {
	e.requestId = requestId
	return e
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
