package provider

import (
	"context"

	"github.com/cloud-idaas/idaas-go-core-sdk/credential"
)

// WithContextShim 把只实现 GetCredential() 的旧 provider 适配为新接口
// IDaaSCredentialProvider（含 GetCredentialWithContext）。Go 无默认方法使新增
// *WithContext 方法成为破坏性变更，外部自定义 provider 可用本 shim 过渡：
//
//	shim := provider.NewWithContextShim(oldProvider) // 满足新 IDaaSCredentialProvider
//	cred, err := shim.GetCredentialWithContext(ctx)
//
// 注意：shim 的 GetCredentialWithContext 内部调用旧 provider 的 GetCredential()，
// ctx 无法透传到旧实现的 HTTP 调用（仅做取消检查）。需真正 ctx 透传时，
// 外部 provider 应直接实现 GetCredentialWithContext。
type WithContextShim struct {
	inner IDaaSCredentialProviderNoCtx
}

// IDaaSCredentialProviderNoCtx 是只含 GetCredential() 的旧接口，
// 便于外部代码用类型断言区分"是否已原生支持 ctx"。
type IDaaSCredentialProviderNoCtx interface {
	GetCredential() (credential.IDaaSCredential, error)
}

// NewWithContextShim 创建适配器，使旧 provider 满足新 IDaaSCredentialProvider 接口。
func NewWithContextShim(inner IDaaSCredentialProviderNoCtx) *WithContextShim {
	return &WithContextShim{inner: inner}
}

func (s *WithContextShim) GetCredential() (credential.IDaaSCredential, error) {
	return s.inner.GetCredential()
}

// GetCredentialWithContext 委托给旧 provider 的 GetCredential()。旧实现忽略 ctx，
// 这里至少检查 ctx 是否已取消（已取消则立即返回，避免调用不支持取消的旧 provider
// 后再丢弃结果）；nil ctx 视为未取消，向后兼容旧测试传入 nil 的场景。
func (s *WithContextShim) GetCredentialWithContext(ctx context.Context) (credential.IDaaSCredential, error) {
	if ctx != nil {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
	}
	return s.inner.GetCredential()
}
