package provider

type JwtClientAssertionProvider interface {
	CreateAssertion() (string, error)
}
