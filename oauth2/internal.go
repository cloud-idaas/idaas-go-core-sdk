package oauth2

import (
	"encoding/json"
	"strconv"

	"github.com/aliyun/idaas-go-core-sdk/constants"
	"github.com/aliyun/idaas-go-core-sdk/credential"
	"github.com/aliyun/idaas-go-core-sdk/domain"
	"github.com/aliyun/idaas-go-core-sdk/enums"
	"github.com/aliyun/idaas-go-core-sdk/errors"
)

// postFormForToken 是 OAuth2 token endpoint / device authorization endpoint
// 全部 form POST 请求的通用 helper。它做三件事：
//  1. 用 application/x-www-form-urlencoded 提交给定的 form
//  2. 失败时尝试把响应解析为标准 OAuth2Error（RFC 6749 §5.2），结构化抛出
//  3. 成功时把响应反序列化为 out（必须是非 nil 指针）
//
// 此 helper 把原本 14 个 GetTokenByXxx 方法尾部完全相同的 4 段样板代码（HTTP 错误 /
// JSON 解析 / 状态码拼接）抽取出来，避免漏改与不一致。
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

// postFormWithHeaders 是真正干活的私有实现：所有 form POST 共用此处。
// extraHeaders 为 nil 时表示无额外 header；不会覆盖必备的 Content-Type。
func (u *OAuth2TokenUtil) postFormWithHeaders(
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

	resp, err := u.httpClient.Execute(&domain.HttpRequest{
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
		return parseOAuth2Error(resp.StatusCode, resp.Body)
	}
	if err := json.Unmarshal(resp.Body, out); err != nil {
		return errors.NewEncodingError("EncodingError", "Failed to parse token response", err)
	}
	return nil
}

// parseOAuth2Error 尝试把 4xx/5xx 响应解析为 OAuth2Error；解析失败时降级为通用 HttpError。
// 这样调用方可以用 errors.As(&oauth2Err) 按 OAuth2 标准 error code 做分支（如
// authorization_pending / slow_down / access_denied / expired_token / invalid_grant）。
func parseOAuth2Error(statusCode int, body []byte) error {
	var oauthErr errors.OAuth2Error
	rawBody := string(body)
	if jsonErr := json.Unmarshal(body, &oauthErr); jsonErr == nil && oauthErr.OAuthCode != "" {
		oauthErr.HTTPStatus = statusCode
		oauthErr.RawBody = rawBody
		return &oauthErr
	}
	// 非标准响应（或 body 不是 JSON）→ 兜底返回通用 HttpError，保留原始 body 便于排查
	return errors.NewHttpError(
		"ClientError",
		"HTTP request failed (HTTP "+strconv.Itoa(statusCode)+"): "+rawBody,
		statusCode,
		nil,
	)
}
