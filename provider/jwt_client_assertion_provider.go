package provider

// JwtClientAssertionProvider JWT Client Assertion 提供者接口 (§4.2.3)
type JwtClientAssertionProvider interface {
	// CreateAssertion 创建 JWT assertion
	CreateAssertion() (string, error)
}
