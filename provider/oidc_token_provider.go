package provider

// OidcTokenProvider OIDC Token 提供者接口 (§4.2.3)
type OidcTokenProvider interface {
	// GetOidcToken 获取 OIDC Token
	GetOidcToken() (string, error)
}
