package provider

import (
	"context"

	"github.com/cloud-idaas/idaas-go-core-sdk/credential"
)

// TokenExchangeRequest 封装 RFC 8693 Token Exchange 的全部参数。
//
// 用请求结构体替代两个裸 string 位置参数,避免 subjectToken / actorToken 传反,
// 同时支持 token type、requested_token_type、scope 等可扩展字段。
type TokenExchangeRequest struct {
	// SubjectToken 被交换的令牌(必填)
	SubjectToken string
	// SubjectTokenType subject_token 的类型,默认 urn:ietf:params:oauth:token-type:access_token
	SubjectTokenType string
	// ActorToken 执行令牌交换的 actor 令牌(可选,用于 delegation 场景)
	ActorToken string
	// ActorTokenType actor_token 的类型
	ActorTokenType string
	// RequestedTokenType 期望获得的令牌类型
	RequestedTokenType string
	// Scope 请求的 scope(可选,为空时使用 provider 绑定的 scope)
	Scope string
}

// IDaaSTokenExchangeCredentialProvider 令牌交换凭证提供者接口
type IDaaSTokenExchangeCredentialProvider interface {
	// ExchangeToken 交换令牌。
	// 内部等价于 ExchangeTokenWithContext(context.Background(), req)。
	ExchangeToken(req TokenExchangeRequest) (credential.IDaaSCredential, error)

	// ExchangeTokenWithContext 交换令牌,带 context。
	// ctx 透传到 token endpoint 请求,使令牌交换可被上层请求取消。
	ExchangeTokenWithContext(ctx context.Context, req TokenExchangeRequest) (credential.IDaaSCredential, error)
}
