package provider

// Pkcs7AttestedDocumentProvider PKCS7 认证文档提供者接口 (§4.2.3)
type Pkcs7AttestedDocumentProvider interface {
	// GetAttestedDocument 获取认证文档
	GetAttestedDocument() (string, error)
}
