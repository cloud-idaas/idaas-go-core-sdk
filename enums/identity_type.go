package enums

// AuthenticationIdentityEnum 枚举 - 与 Java/Python SDK 保持一致
type AuthenticationIdentityEnum string

const (
	AuthenticationIdentityClient AuthenticationIdentityEnum = "CLIENT"
	AuthenticationIdentityHuman  AuthenticationIdentityEnum = "HUMAN"
)
