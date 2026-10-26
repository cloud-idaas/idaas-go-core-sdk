package oauth2

import (
	"context"
	"encoding/base64"
	"net/url"

	"github.com/cloud-idaas/idaas-go-core-sdk/constants"
	"github.com/cloud-idaas/idaas-go-core-sdk/credential"
	"github.com/cloud-idaas/idaas-go-core-sdk/domain"
	"github.com/cloud-idaas/idaas-go-core-sdk/http"
)

// OAuth2TokenUtil OAuth2 令牌工具类
//
// 设计上所有 token endpoint 请求统一走 postFormForToken / postFormForTokenResponse
// helper（见 internal.go）。Helper 负责：
// 1. 用 application/x-www-form-urlencoded 提交
// 2. 把 4xx/5xx 解析为 *errors.OAuth2Error（RFC 6749 标准字段），调用方可用 errors.As 分支
// 3. 把成功响应反序列化为 *IDaaSTokenResponse 或 *DeviceCodeResponse
//
// 这样消除 14 份重复的 "Execute → IsSuccess → json.Unmarshal" 样板代码，避免漏改。
type OAuth2TokenUtil struct {
	httpClient http.HttpClient
}

func NewOAuth2TokenUtil(httpClient http.HttpClient) *OAuth2TokenUtil {
	return &OAuth2TokenUtil{httpClient: httpClient}
}

// setIfNotEmpty 仅在值非空时写入 form，减少调用方重复的 if 判断
func setIfNotEmpty(values url.Values, key, value string) {
	if value != "" {
		values.Set(key, value)
	}
}

// basicAuthHeader 构造 RFC 6749 / RFC 2617 的 HTTP Basic Authorization 头。
//
// 规范要求 client_id 与 client_secret 在拼接前各自做 application/x-www-form-urlencoded
// 编码再 base64。对纯字母数字的凭证是 no-op，但对含 ':' / '+' / 空格 / '=' 等保留字符的
// 凭证能避免 basic 头被截断或冒号定位错误。与 internal/implementation.buildClientAuthentication
// 的 client_secret_basic 分支保持一致，消除两处实现的编码口径分歧。
func basicAuthHeader(clientId, clientSecret string) string {
	encoded := url.QueryEscape(clientId) + ":" + url.QueryEscape(clientSecret)
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(encoded))
}

// GetTokenByClientCredentials 通过 client_credentials 获取令牌（client_secret_post 方式）
func (u *OAuth2TokenUtil) GetTokenByClientCredentials(
	tokenEndpoint string,
	clientId string,
	clientSecret string,
	scope string,
) (*credential.IDaaSTokenResponse, error) {
	form := url.Values{}
	form.Set(constants.ParamClientID, clientId)
	form.Set(constants.ParamClientSecret, clientSecret)
	form.Set(constants.ParamGrantType, constants.GrantTypeClientCredentials)
	setIfNotEmpty(form, constants.ParamScope, scope)
	return u.postFormForTokenResponse(tokenEndpoint, form.Encode())
}

// GetTokenByClientCredentialsBasic 通过 client_credentials 获取令牌（client_secret_basic 方式，使用 HTTP Basic Auth）
//
// HTTP Basic Auth 头与 form body 同时携带 grant_type=client_credentials。
// 这里独立保留方法体（而非走 helper），因为它需要额外的 Authorization 头。
func (u *OAuth2TokenUtil) GetTokenByClientCredentialsBasic(
	tokenEndpoint string,
	clientId string,
	clientSecret string,
	scope string,
) (*credential.IDaaSTokenResponse, error) {
	form := url.Values{}
	form.Set(constants.ParamGrantType, constants.GrantTypeClientCredentials)
	setIfNotEmpty(form, constants.ParamScope, scope)

	auth := basicAuthHeader(clientId, clientSecret)
	return u.postFormWithHeadersForTokenResponse(tokenEndpoint, form.Encode(), map[string]string{
		"Authorization": auth,
	})
}

// GetTokenByJwtBearer 通过 jwt-bearer grant 获取令牌
func (u *OAuth2TokenUtil) GetTokenByJwtBearer(
	tokenEndpoint string,
	clientId string,
	assertion string,
	scope string,
) (*credential.IDaaSTokenResponse, error) {
	form := url.Values{}
	form.Set(constants.ParamClientID, clientId)
	form.Set(constants.ParamGrantType, constants.GrantTypeJwtBearer)
	form.Set(constants.ParamAssertion, assertion)
	setIfNotEmpty(form, constants.ParamScope, scope)
	return u.postFormForTokenResponse(tokenEndpoint, form.Encode())
}

// GetTokenByClientCredentialsJwtAssertion 通过 client_credentials + JWT 客户端断言获取令牌
// 用于 private_key_jwt 与 client_secret_jwt 两种认证方式
// grant_type = client_credentials, client_assertion_type = urn:ietf:params:oauth:client-assertion-type:jwt-bearer
//
// 阿里云 IDaaS 官方规范要求 form 必须同时包含：
//
//	client_id / grant_type / client_assertion_type / client_assertion / scope（可选）
//
// 注意：RFC 7521 建议使用 client_assertion 时不传 client_id，但阿里云 IDaaS
// 实际实现要求 client_id 必传，否则返回 401 authentication_required。以官方为准。
func (u *OAuth2TokenUtil) GetTokenByClientCredentialsJwtAssertion(
	tokenEndpoint string,
	clientId string,
	clientAssertion string,
	scope string,
) (*credential.IDaaSTokenResponse, error) {
	form := url.Values{}
	form.Set(constants.ParamClientID, clientId)
	form.Set(constants.ParamGrantType, constants.GrantTypeClientCredentials)
	form.Set(constants.ParamClientAssertionType, constants.AssertionTypeJwtBearer)
	form.Set(constants.ParamClientAssertion, clientAssertion)
	setIfNotEmpty(form, constants.ParamScope, scope)
	return u.postFormForTokenResponse(tokenEndpoint, form.Encode())
}

// GetTokenByX509JwtBearer 通过 PrivateCA X509 证书 + JWT 客户端断言获取令牌（PCA）
// 阿里云 IDaaS 私有规范：client_assertion_type = urn:cloud:idaas:params:oauth:client-assertion-type:x509-jwt-bearer
// 额外字段：client_x509（叶子证书 PEM）、client_x509_chain（中间证书链 PEM）、application_federated_credential_name
//
// 阿里云 IDaaS 要求 form 必须包含 client_id（即便使用 client_assertion 认证），否则会返回 401。
func (u *OAuth2TokenUtil) GetTokenByX509JwtBearer(
	tokenEndpoint string,
	clientId string,
	clientAssertion string,
	clientX509 string,
	clientX509Chain string,
	federatedCredentialName string,
	scope string,
) (*credential.IDaaSTokenResponse, error) {
	form := url.Values{}
	form.Set(constants.ParamClientID, clientId)
	form.Set(constants.ParamGrantType, constants.GrantTypeClientCredentials)
	form.Set(constants.ParamClientAssertionType, constants.AssertionTypeX509JwtBearer)
	form.Set(constants.ParamClientAssertion, clientAssertion)
	form.Set(constants.ParamClientX509, clientX509)
	setIfNotEmpty(form, constants.ParamClientX509Chain, clientX509Chain)
	setIfNotEmpty(form, constants.ParamApplicationFederatedCredentialName, federatedCredentialName)
	setIfNotEmpty(form, constants.ParamScope, scope)
	return u.postFormForTokenResponse(tokenEndpoint, form.Encode())
}

// GetTokenWithPKCS7AttestedDocument 通过 PKCS7 attested document 获取令牌（PKCS7 联邦认证）
//
// 与阿里云 Java SDK OAuth2TokenUtil.getTokenWithPKCS7AttestedDocument 完全对齐：
//
//	grant_type = client_credentials
//	client_id = clientId
//	client_assertion_type = urn:cloud:idaas:params:oauth:client-assertion-type:pkcs7-bearer
//	client_assertion = pkcs7 attested document
//	application_federated_credential_name = federatedCredentialName
//	scope = scope
//
// 适用场景：authnMethod = PKCS7、clientDeployEnvironment = ALIBABA_CLOUD_ECS
func (u *OAuth2TokenUtil) GetTokenWithPKCS7AttestedDocument(
	tokenEndpoint string,
	clientId string,
	federatedCredentialName string,
	pkcs7AttestedDocument string,
	scope string,
) (*credential.IDaaSTokenResponse, error) {
	form := url.Values{}
	form.Set(constants.ParamClientID, clientId)
	form.Set(constants.ParamGrantType, constants.GrantTypeClientCredentials)
	form.Set(constants.ParamApplicationFederatedCredentialName, federatedCredentialName)
	form.Set(constants.ParamClientAssertionType, constants.AssertionTypePkcs7Bearer)
	form.Set(constants.ParamClientAssertion, pkcs7AttestedDocument)
	setIfNotEmpty(form, constants.ParamScope, scope)
	return u.postFormForTokenResponse(tokenEndpoint, form.Encode())
}

// GetTokenWithOIDCFederatedCredential 通过 OIDC token 获取令牌（OIDC 联邦认证）
//
// 与阿里云 Java SDK OAuth2TokenUtil.getTokenWithOIDCFederatedCredential 完全对齐：
//
//	grant_type = client_credentials
//	client_id = clientId
//	client_assertion_type = urn:cloud:idaas:params:oauth:client-assertion-type:id-token-bearer
//	client_assertion = OIDC token
//	application_federated_credential_name = federatedCredentialName
//	scope = scope
//
// 适用场景：authnMethod = OIDC、clientDeployEnvironment = KUBERNETES（或 COMPUTER）
func (u *OAuth2TokenUtil) GetTokenWithOIDCFederatedCredential(
	tokenEndpoint string,
	clientId string,
	federatedCredentialName string,
	oidcToken string,
	scope string,
) (*credential.IDaaSTokenResponse, error) {
	form := url.Values{}
	form.Set(constants.ParamClientID, clientId)
	form.Set(constants.ParamGrantType, constants.GrantTypeClientCredentials)
	form.Set(constants.ParamApplicationFederatedCredentialName, federatedCredentialName)
	form.Set(constants.ParamClientAssertionType, constants.AssertionTypeIdTokenBearer)
	form.Set(constants.ParamClientAssertion, oidcToken)
	setIfNotEmpty(form, constants.ParamScope, scope)
	return u.postFormForTokenResponse(tokenEndpoint, form.Encode())
}

// GetTokenByRefreshToken 通过 refresh_token 获取新令牌
func (u *OAuth2TokenUtil) GetTokenByRefreshToken(
	tokenEndpoint string,
	clientId string,
	clientSecret string,
	refreshToken string,
	scope string,
) (*credential.IDaaSTokenResponse, error) {
	form := url.Values{}
	form.Set(constants.ParamClientID, clientId)
	form.Set(constants.ParamClientSecret, clientSecret)
	form.Set(constants.ParamGrantType, constants.GrantTypeRefreshToken)
	form.Set(constants.ParamRefreshToken, refreshToken)
	setIfNotEmpty(form, constants.ParamScope, scope)
	return u.postFormForTokenResponse(tokenEndpoint, form.Encode())
}

// TokenExchange 令牌交换。内部委托给 TokenExchangeWithContext。
func (u *OAuth2TokenUtil) TokenExchange(
	tokenEndpoint string,
	clientId string,
	clientSecret string,
	subjectToken string,
	subjectTokenType string,
	actorToken string,
	actorTokenType string,
	requestedTokenType string,
	scope string,
) (*credential.IDaaSTokenResponse, error) {
	return u.TokenExchangeWithContext(
		context.Background(),
		tokenEndpoint,
		clientId,
		clientSecret,
		subjectToken,
		subjectTokenType,
		actorToken,
		actorTokenType,
		requestedTokenType,
		scope,
	)
}

// TokenExchangeWithContext 令牌交换,带 context。ctx 透传到 token endpoint 请求。
func (u *OAuth2TokenUtil) TokenExchangeWithContext(
	ctx context.Context,
	tokenEndpoint string,
	clientId string,
	clientSecret string,
	subjectToken string,
	subjectTokenType string,
	actorToken string,
	actorTokenType string,
	requestedTokenType string,
	scope string,
) (*credential.IDaaSTokenResponse, error) {
	form := url.Values{}
	form.Set(constants.ParamClientID, clientId)
	form.Set(constants.ParamClientSecret, clientSecret)
	return u.TokenExchangeWithClientAuthWithContext(
		ctx,
		tokenEndpoint,
		ClientAuthentication{Form: form},
		subjectToken,
		subjectTokenType,
		actorToken,
		actorTokenType,
		requestedTokenType,
		scope,
	)
}

// ClientAuthentication 是 token endpoint 请求的客户端认证部分：Form 里的字段
// （client_id、client_secret / client_assertion 等）与额外的 HTTP header
// （client_secret_basic 的 Authorization）。两者都可以为空。
type ClientAuthentication struct {
	Form    url.Values
	Headers map[string]string
}

// TokenExchangeWithClientAuthWithContext 令牌交换 (RFC 8693)，客户端认证方式由 auth 决定，
// 与 Java SDK 一致支持全部 authn method。auth.Form 不会被修改。
func (u *OAuth2TokenUtil) TokenExchangeWithClientAuthWithContext(
	ctx context.Context,
	tokenEndpoint string,
	auth ClientAuthentication,
	subjectToken string,
	subjectTokenType string,
	actorToken string,
	actorTokenType string,
	requestedTokenType string,
	scope string,
) (*credential.IDaaSTokenResponse, error) {
	form := url.Values{}
	for k, v := range auth.Form {
		form[k] = append([]string(nil), v...)
	}
	form.Set(constants.ParamGrantType, constants.GrantTypeTokenExchange)
	form.Set(constants.ParamSubjectToken, subjectToken)
	form.Set(constants.ParamSubjectTokenType, subjectTokenType)
	if actorToken != "" {
		form.Set(constants.ParamActorToken, actorToken)
		form.Set(constants.ParamActorTokenType, actorTokenType)
	}
	setIfNotEmpty(form, constants.ParamRequestedTokenType, requestedTokenType)
	setIfNotEmpty(form, constants.ParamScope, scope)
	return u.postFormWithHeadersForTokenResponseWithContext(ctx, tokenEndpoint, form.Encode(), auth.Headers)
}

// GetDeviceCode 获取 Device Code
func (u *OAuth2TokenUtil) GetDeviceCode(
	deviceAuthorizationEndpoint string,
	clientId string,
	scope string,
) (*domain.DeviceCodeResponse, error) {
	form := url.Values{}
	form.Set(constants.ParamClientID, clientId)
	setIfNotEmpty(form, constants.ParamScope, scope)

	var deviceCodeResp domain.DeviceCodeResponse
	if err := u.postFormForToken(deviceAuthorizationEndpoint, form.Encode(), &deviceCodeResp); err != nil {
		return nil, err
	}
	return &deviceCodeResp, nil
}

// GetTokenByDeviceCode 通过 Device Code 获取令牌
//
// 错误处理由 helper 完成：4xx 响应若是 OAuth2 标准错误体（如
// {"error":"authorization_pending"}）会被解析为 *errors.OAuth2Error，
// 调用方可用 errors.As 按 OAuthCode 分支处理（参见 human_federated_oidc_provider）。
func (u *OAuth2TokenUtil) GetTokenByDeviceCode(
	tokenEndpoint string,
	clientId string,
	deviceCode string,
) (*credential.IDaaSTokenResponse, error) {
	form := url.Values{}
	form.Set(constants.ParamClientID, clientId)
	form.Set(constants.ParamGrantType, constants.GrantTypeDeviceCode)
	form.Set(constants.ParamDeviceCode, deviceCode)
	return u.postFormForTokenResponse(tokenEndpoint, form.Encode())
}

// RefreshToken 通过 refresh_token 获取新令牌（无 client_secret 简化版，仅 兼容入口）
func (u *OAuth2TokenUtil) RefreshToken(
	tokenEndpoint string,
	clientId string,
	refreshToken string,
) (*credential.IDaaSTokenResponse, error) {
	form := url.Values{}
	form.Set(constants.ParamGrantType, constants.GrantTypeRefreshToken)
	form.Set(constants.ParamClientID, clientId)
	form.Set(constants.ParamRefreshToken, refreshToken)
	return u.postFormForTokenResponse(tokenEndpoint, form.Encode())
}

func (u *OAuth2TokenUtil) GetTokenByClientCredentialsWithContext(
	ctx context.Context,
	tokenEndpoint, clientId, clientSecret, scope string,
) (*credential.IDaaSTokenResponse, error) {
	form := url.Values{}
	form.Set(constants.ParamClientID, clientId)
	form.Set(constants.ParamClientSecret, clientSecret)
	form.Set(constants.ParamGrantType, constants.GrantTypeClientCredentials)
	setIfNotEmpty(form, constants.ParamScope, scope)
	return u.postFormForTokenResponseWithContext(ctx, tokenEndpoint, form.Encode())
}

func (u *OAuth2TokenUtil) GetTokenByClientCredentialsBasicWithContext(
	ctx context.Context,
	tokenEndpoint, clientId, clientSecret, scope string,
) (*credential.IDaaSTokenResponse, error) {
	form := url.Values{}
	form.Set(constants.ParamGrantType, constants.GrantTypeClientCredentials)
	setIfNotEmpty(form, constants.ParamScope, scope)
	auth := basicAuthHeader(clientId, clientSecret)
	return u.postFormWithHeadersForTokenResponseWithContext(ctx, tokenEndpoint, form.Encode(), map[string]string{
		"Authorization": auth,
	})
}

func (u *OAuth2TokenUtil) GetTokenByJwtBearerWithContext(
	ctx context.Context,
	tokenEndpoint, clientId, assertion, scope string,
) (*credential.IDaaSTokenResponse, error) {
	form := url.Values{}
	form.Set(constants.ParamClientID, clientId)
	form.Set(constants.ParamGrantType, constants.GrantTypeJwtBearer)
	form.Set(constants.ParamAssertion, assertion)
	setIfNotEmpty(form, constants.ParamScope, scope)
	return u.postFormForTokenResponseWithContext(ctx, tokenEndpoint, form.Encode())
}

func (u *OAuth2TokenUtil) GetTokenByClientCredentialsJwtAssertionWithContext(
	ctx context.Context,
	tokenEndpoint, clientId, clientAssertion, scope string,
) (*credential.IDaaSTokenResponse, error) {
	form := url.Values{}
	form.Set(constants.ParamClientID, clientId)
	form.Set(constants.ParamGrantType, constants.GrantTypeClientCredentials)
	form.Set(constants.ParamClientAssertionType, constants.AssertionTypeJwtBearer)
	form.Set(constants.ParamClientAssertion, clientAssertion)
	setIfNotEmpty(form, constants.ParamScope, scope)
	return u.postFormForTokenResponseWithContext(ctx, tokenEndpoint, form.Encode())
}

func (u *OAuth2TokenUtil) GetTokenByX509JwtBearerWithContext(
	ctx context.Context,
	tokenEndpoint, clientId, clientAssertion, clientX509, clientX509Chain, federatedCredentialName, scope string,
) (*credential.IDaaSTokenResponse, error) {
	form := url.Values{}
	form.Set(constants.ParamClientID, clientId)
	form.Set(constants.ParamGrantType, constants.GrantTypeClientCredentials)
	form.Set(constants.ParamClientAssertionType, constants.AssertionTypeX509JwtBearer)
	form.Set(constants.ParamClientAssertion, clientAssertion)
	form.Set(constants.ParamClientX509, clientX509)
	setIfNotEmpty(form, constants.ParamClientX509Chain, clientX509Chain)
	setIfNotEmpty(form, constants.ParamApplicationFederatedCredentialName, federatedCredentialName)
	setIfNotEmpty(form, constants.ParamScope, scope)
	return u.postFormForTokenResponseWithContext(ctx, tokenEndpoint, form.Encode())
}

func (u *OAuth2TokenUtil) GetTokenWithPKCS7AttestedDocumentWithContext(
	ctx context.Context,
	tokenEndpoint, clientId, federatedCredentialName, pkcs7AttestedDocument, scope string,
) (*credential.IDaaSTokenResponse, error) {
	form := url.Values{}
	form.Set(constants.ParamClientID, clientId)
	form.Set(constants.ParamGrantType, constants.GrantTypeClientCredentials)
	form.Set(constants.ParamApplicationFederatedCredentialName, federatedCredentialName)
	form.Set(constants.ParamClientAssertionType, constants.AssertionTypePkcs7Bearer)
	form.Set(constants.ParamClientAssertion, pkcs7AttestedDocument)
	setIfNotEmpty(form, constants.ParamScope, scope)
	return u.postFormForTokenResponseWithContext(ctx, tokenEndpoint, form.Encode())
}

func (u *OAuth2TokenUtil) GetTokenWithOIDCFederatedCredentialWithContext(
	ctx context.Context,
	tokenEndpoint, clientId, federatedCredentialName, oidcToken, scope string,
) (*credential.IDaaSTokenResponse, error) {
	form := url.Values{}
	form.Set(constants.ParamClientID, clientId)
	form.Set(constants.ParamGrantType, constants.GrantTypeClientCredentials)
	form.Set(constants.ParamApplicationFederatedCredentialName, federatedCredentialName)
	form.Set(constants.ParamClientAssertionType, constants.AssertionTypeIdTokenBearer)
	form.Set(constants.ParamClientAssertion, oidcToken)
	setIfNotEmpty(form, constants.ParamScope, scope)
	return u.postFormForTokenResponseWithContext(ctx, tokenEndpoint, form.Encode())
}

func (u *OAuth2TokenUtil) GetDeviceCodeWithContext(
	ctx context.Context,
	deviceAuthorizationEndpoint, clientId, scope string,
) (*domain.DeviceCodeResponse, error) {
	form := url.Values{}
	form.Set(constants.ParamClientID, clientId)
	setIfNotEmpty(form, constants.ParamScope, scope)

	var deviceCodeResp domain.DeviceCodeResponse
	if err := u.postFormForTokenWithContext(ctx, deviceAuthorizationEndpoint, form.Encode(), &deviceCodeResp); err != nil {
		return nil, err
	}
	return &deviceCodeResp, nil
}

func (u *OAuth2TokenUtil) GetTokenByDeviceCodeWithContext(
	ctx context.Context,
	tokenEndpoint, clientId, deviceCode string,
) (*credential.IDaaSTokenResponse, error) {
	form := url.Values{}
	form.Set(constants.ParamClientID, clientId)
	form.Set(constants.ParamGrantType, constants.GrantTypeDeviceCode)
	form.Set(constants.ParamDeviceCode, deviceCode)
	return u.postFormForTokenResponseWithContext(ctx, tokenEndpoint, form.Encode())
}

func (u *OAuth2TokenUtil) RefreshTokenWithContext(
	ctx context.Context,
	tokenEndpoint, clientId, refreshToken string,
) (*credential.IDaaSTokenResponse, error) {
	form := url.Values{}
	form.Set(constants.ParamGrantType, constants.GrantTypeRefreshToken)
	form.Set(constants.ParamClientID, clientId)
	form.Set(constants.ParamRefreshToken, refreshToken)
	return u.postFormForTokenResponseWithContext(ctx, tokenEndpoint, form.Encode())
}
