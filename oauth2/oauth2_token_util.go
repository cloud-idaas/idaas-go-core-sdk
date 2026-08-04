package oauth2

import (
	"encoding/base64"
	"net/url"

	"github.com/cloud-idaas/idaas-go-core-sdk/constants"
	"github.com/cloud-idaas/idaas-go-core-sdk/credential"
	"github.com/cloud-idaas/idaas-go-core-sdk/domain"
	"github.com/cloud-idaas/idaas-go-core-sdk/http"
)

// OAuth2TokenUtil OAuth2 令牌工具类 (§6)
//
// 设计上所有 token endpoint 请求统一走 postFormForToken / postFormForTokenResponse
// helper（见 internal.go）。Helper 负责：
//  1. 用 application/x-www-form-urlencoded 提交
//  2. 把 4xx/5xx 解析为 *errors.OAuth2Error（RFC 6749 §5.2 标准字段），调用方可用 errors.As 分支
//  3. 把成功响应反序列化为 *IDaaSTokenResponse 或 *DeviceCodeResponse
//
// 这样消除 14 份重复的 "Execute → IsSuccess → json.Unmarshal" 样板代码，避免漏改。
type OAuth2TokenUtil struct {
	httpClient http.HttpClient
}

// NewOAuth2TokenUtil 创建 OAuth2TokenUtil
func NewOAuth2TokenUtil(httpClient http.HttpClient) *OAuth2TokenUtil {
	return &OAuth2TokenUtil{httpClient: httpClient}
}

// setIfNotEmpty 仅在值非空时写入 form，减少调用方重复的 if 判断
func setIfNotEmpty(values url.Values, key, value string) {
	if value != "" {
		values.Set(key, value)
	}
}

// GetTokenByClientCredentials 通过 client_credentials 获取令牌（client_secret_post 方式） (§6.1)
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

// GetTokenByClientCredentialsBasic 通过 client_credentials 获取令牌（client_secret_basic 方式，使用 HTTP Basic Auth） (§6.1)
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

	auth := base64.StdEncoding.EncodeToString([]byte(clientId + ":" + clientSecret))
	return u.postFormWithHeadersForTokenResponse(tokenEndpoint, form.Encode(), map[string]string{
		"Authorization": "Basic " + auth,
	})
}

// GetTokenByJwtBearer 通过 jwt-bearer grant 获取令牌 (§6.2)
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
// 注意：RFC 7521 §4.2 建议使用 client_assertion 时不传 client_id，但阿里云 IDaaS
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
//	grant_type             = client_credentials
//	client_id              = clientId
//	client_assertion_type  = urn:cloud:idaas:params:oauth:client-assertion-type:pkcs7-bearer
//	client_assertion       = pkcs7 attested document
//	application_federated_credential_name = federatedCredentialName
//	scope                  = scope
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
//	grant_type             = client_credentials
//	client_id              = clientId
//	client_assertion_type  = urn:cloud:idaas:params:oauth:client-assertion-type:id-token-bearer
//	client_assertion       = OIDC token
//	application_federated_credential_name = federatedCredentialName
//	scope                  = scope
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

// GetTokenByRefreshToken 通过 refresh_token 获取新令牌 (§6.3)
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

// TokenExchange 令牌交换 (§6.4)
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
	form := url.Values{}
	form.Set(constants.ParamClientID, clientId)
	form.Set(constants.ParamClientSecret, clientSecret)
	form.Set(constants.ParamGrantType, constants.GrantTypeTokenExchange)
	form.Set(constants.ParamSubjectToken, subjectToken)
	form.Set(constants.ParamSubjectTokenType, subjectTokenType)
	if actorToken != "" {
		form.Set(constants.ParamActorToken, actorToken)
		form.Set(constants.ParamActorTokenType, actorTokenType)
	}
	setIfNotEmpty(form, constants.ParamRequestedTokenType, requestedTokenType)
	setIfNotEmpty(form, constants.ParamScope, scope)
	return u.postFormForTokenResponse(tokenEndpoint, form.Encode())
}

// GetDeviceCode 获取 Device Code (§6.5)
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

// GetTokenByDeviceCode 通过 Device Code 获取令牌 (§6.6)
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

// RefreshToken 通过 refresh_token 获取新令牌（无 client_secret 简化版，仅 §6.3 兼容入口）
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
