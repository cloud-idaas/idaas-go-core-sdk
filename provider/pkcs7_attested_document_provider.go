package provider

import "context"

type Pkcs7AttestedDocumentProvider interface {
	GetAttestedDocument() (string, error)
	// GetAttestedDocumentWithContext 获取认证文档,带 context。
	// ctx 透传到元数据服务请求,使调用方可取消长时间挂起的元数据调用。
	GetAttestedDocumentWithContext(ctx context.Context) (string, error)
}
