package provider

import "context"

type OidcTokenProvider interface {
	GetOidcToken() (string, error)
	// GetOidcTokenWithContext 获取 OIDC Token,带 context。
	// ctx 透传到元数据服务请求,使调用方可取消长时间挂起的元数据调用。
	GetOidcTokenWithContext(ctx context.Context) (string, error)
}
