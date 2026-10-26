package oauth2

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/cloud-idaas/idaas-go-core-sdk/constants"
	"github.com/cloud-idaas/idaas-go-core-sdk/credential"
	"github.com/cloud-idaas/idaas-go-core-sdk/domain"
	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
	"github.com/cloud-idaas/idaas-go-core-sdk/errors"
	"github.com/cloud-idaas/idaas-go-core-sdk/util"
)

// postFormForToken 是 OAuth2 token endpoint / device authorization endpoint
// 全部 form POST 请求的通用 helper：form-urlencoded 提交 → 失败解析为 OAuth2Error →
// 成功反序列化到 out（必须是非 nil 指针）。内部委托给 postFormWithHeadersWithContext。
func (u *OAuth2TokenUtil) postFormForToken(endpoint, formEncoded string, out interface{}) error {
	return u.postFormWithHeaders(endpoint, formEncoded, nil, out)
}

// postFormForTokenResponse 是 postFormForToken 针对 IDaaSTokenResponse 的便捷封装
func (u *OAuth2TokenUtil) postFormForTokenResponse(endpoint, formEncoded string) (*credential.IDaaSTokenResponse, error) {
	var tokenResp credential.IDaaSTokenResponse
	if err := u.postFormWithHeaders(endpoint, formEncoded, nil, &tokenResp); err != nil {
		return nil, err
	}
	return &tokenResp, nil
}

// postFormWithHeadersForTokenResponse 用于需要额外 HTTP header 的场景（如 client_secret_basic
// 需要 Authorization: Basic xxx header）。底层与 postFormForToken 共用同一段实现。
func (u *OAuth2TokenUtil) postFormWithHeadersForTokenResponse(
	endpoint, formEncoded string,
	extraHeaders map[string]string,
) (*credential.IDaaSTokenResponse, error) {
	var tokenResp credential.IDaaSTokenResponse
	if err := u.postFormWithHeaders(endpoint, formEncoded, extraHeaders, &tokenResp); err != nil {
		return nil, err
	}
	return &tokenResp, nil
}

func (u *OAuth2TokenUtil) postFormForTokenResponseWithContext(
	ctx context.Context, endpoint, formEncoded string,
) (*credential.IDaaSTokenResponse, error) {
	var tokenResp credential.IDaaSTokenResponse
	if err := u.postFormWithHeadersWithContext(ctx, endpoint, formEncoded, nil, &tokenResp); err != nil {
		return nil, err
	}
	return &tokenResp, nil
}

// postFormForTokenWithContext 用于 device authorization endpoint 等非 token-response 的 form POST。
func (u *OAuth2TokenUtil) postFormForTokenWithContext(
	ctx context.Context, endpoint, formEncoded string, out interface{},
) error {
	return u.postFormWithHeadersWithContext(ctx, endpoint, formEncoded, nil, out)
}

func (u *OAuth2TokenUtil) postFormWithHeadersForTokenResponseWithContext(
	ctx context.Context,
	endpoint, formEncoded string,
	extraHeaders map[string]string,
) (*credential.IDaaSTokenResponse, error) {
	var tokenResp credential.IDaaSTokenResponse
	if err := u.postFormWithHeadersWithContext(ctx, endpoint, formEncoded, extraHeaders, &tokenResp); err != nil {
		return nil, err
	}
	return &tokenResp, nil
}

// postFormWithHeaders 是 ctx 透传的旧入口，保持向后兼容。
func (u *OAuth2TokenUtil) postFormWithHeaders(
	endpoint, formEncoded string,
	extraHeaders map[string]string,
	out interface{},
) error {
	return u.postFormWithHeadersWithContext(context.Background(), endpoint, formEncoded, extraHeaders, out)
}

// postFormWithHeadersWithContext 是所有 form POST 共用的私有实现，ctx 透传到 httpClient.ExecuteContext。
// extraHeaders 为 nil 时表示无额外 header；不会覆盖必备的 Content-Type。
func (u *OAuth2TokenUtil) postFormWithHeadersWithContext(
	ctx context.Context,
	endpoint, formEncoded string,
	extraHeaders map[string]string,
	out interface{},
) error {
	headers := make(map[string]string, 1+len(extraHeaders))
	headers[constants.HeaderContentType] = constants.ContentTypeFormUrlEncoded
	for k, v := range extraHeaders {
		// 调用方约定不会覆盖 Content-Type；如果传了，以底层规范为准（保留 form-urlencoded）
		if k == constants.HeaderContentType {
			continue
		}
		headers[k] = v
	}

	resp, err := u.httpClient.ExecuteContext(ctx, &domain.HttpRequest{
		Method:      enums.HttpMethodPost,
		URL:         endpoint,
		Headers:     headers,
		Body:        formEncoded,
		ContentType: enums.ContentTypeForm,
	})
	if err != nil {
		return err
	}
	if !resp.IsSuccess() {
		return parseOAuth2Error(resp)
	}
	if err := json.Unmarshal(resp.Body, out); err != nil {
		// 带 requestId：解析失败意味着服务端返回预期外结构，正是最需对账的场景。
		return errors.NewEncodingError(
			constants.EncodeFailed,
			"Failed to parse token response",
			err,
		).WithRequestId(resp.RequestId())
	}
	// 只对 IDaaSTokenResponse 做完整性校验（access_token 非空、token_type=Bearer），不影响其他 out 类型。
	if tokenResp, ok := out.(*credential.IDaaSTokenResponse); ok {
		if err := tokenResp.ValidateLocalToken(); err != nil {
			// ValidateLocalToken 返回的 CredentialError Cause=nil → RequestId() 返回空串。
			// 服务端返回了 2xx 但 access_token 缺失 / token_type 非 Bearer 等异常,
			// 正是最需要 requestId 去跟服务端对账的场景,此处补齐,与上方 JSON 解析失败路径一致。
			if credErr, ok := err.(*errors.CredentialError); ok {
				return credErr.WithRequestId(resp.RequestId())
			}
			return err
		}
	}
	return nil
}

// parseOAuth2Error 把非 2xx 响应转换为错误，分类规则与 Java/Python 一致：
//   - 4xx：body 是 OAuth2 标准错误时返回 *OAuth2Error，否则返回 Code=ClientError 的 *HttpError。
//   - 5xx：返回 *ServerError，上面解析出的 *OAuth2Error/*HttpError 作为 Cause 保留，
//     调用方可用 errors.As(&serverErr) 判断"可重试"，也仍可用 errors.As(&oauthErr) 读标准 error code。
//
// 入参收整个 *domain.HttpResponse 而非 (statusCode, body)，因为 requestId 可能在响应头里。
func parseOAuth2Error(resp *domain.HttpResponse) error {
	statusCode := resp.StatusCode
	requestId := resp.RequestId()

	// DefaultHttpClient 已用 LimitReader 把 body 封顶到 4 MiB，但整段 body 拼进
	// error message 会撑爆日志与错误链；token 端点是最热的错误路径，截断到 512 字节保留排障前缀。
	truncatedBody := util.TruncateForError(resp.Body, 512)

	var oauthErr errors.OAuth2Error
	if jsonErr := json.Unmarshal(resp.Body, &oauthErr); jsonErr == nil && oauthErr.OAuthCode != "" {
		oauthErr.HTTPStatus = statusCode
		oauthErr.RawBody = truncatedBody
		parsed := oauthErr.WithRequestId(requestId)
		if statusCode >= 500 {
			// parsed.ErrorMessage() 返回完整的 error_description(未截断),可能含 IdP
			// 回显的 refresh_token / client_secret。直接拼进 ServerError.Message 会绕过
			// 上方 truncatedBody 的 512 字节保护,让超长或含敏感信息的文本泄露进
			// 日志 / err.Error()。先经 errors.RedactDescription 脱敏(与 4xx
			// OAuth2Error.Error() 对称),再截断到 512;完整原文仍可通过 errors.As
			// → *OAuth2Error.FullDescription() 获取。
			return errors.NewServerError(
				oauthErr.OAuthCode,
				"OAuth2 server error: "+util.TruncateForError([]byte(errors.RedactDescription(parsed.ErrorMessage())), 512),
				statusCode,
				parsed,
			).WithRequestId(requestId)
		}
		return parsed
	}
	// 非标准响应（或 body 不是 JSON）→ 通用 HttpError，保留(截断后的) body 便于排查。
	// 与 5xx 标准 OAuth2 路径对称：truncatedBody 可能含 IdP 回显的 refresh_token /
	// client_secret 等(非标准错误体更易携带非预期内容)，先经 RedactDescription 脱敏
	// 再拼入 Message，避免经 err.Error() / 异步刷新失败日志明文泄露。完整原文仍可
	// 经 errors.As → *HttpError 取 Message 字段（已脱敏）或 FullDescription 路径获取。
	code := constants.ClientError
	if statusCode >= 500 {
		code = constants.ServerError
	}
	httpErr := errors.NewHttpError(
		code,
		"HTTP request failed (HTTP "+strconv.Itoa(statusCode)+"): "+errors.RedactDescription(truncatedBody),
		statusCode,
		nil,
	).WithRequestId(requestId)
	if statusCode >= 500 {
		return errors.NewServerError(
			constants.ServerError,
			"HTTP request failed (HTTP "+strconv.Itoa(statusCode)+")",
			statusCode,
			httpErr,
		).WithRequestId(requestId)
	}
	return httpErr
}
