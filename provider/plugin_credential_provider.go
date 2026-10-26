package provider

import (
	"context"

	"github.com/cloud-idaas/idaas-go-core-sdk/credential"
)

// PluginCredentialProvider 插件凭证提供者接口
//
// 与 Java SDK com.cloud_idaas.core.provider.PluginCredentialProvider 对齐：
// - GetName() 返回插件唯一名称，用于注册和按 pluginName 查找
// - GetIDaaSCredential(scope) 由插件自行获取完整 token（SDK 不发起 HTTP 请求）
type PluginCredentialProvider interface {
	GetName() string

	// GetIDaaSCredential 根据 scope 获取完整的 IDaaS 凭证
	// 插件自行负责与外部系统交互（如阿里云 EIAM OpenAPI），SDK 不参与
	GetIDaaSCredential(scope string) (credential.IDaaSCredential, error)
}

// PluginCredentialProviderWithContext 是 PluginCredentialProvider 的可选扩展接口。
//
// PluginCredentialProvider.GetIDaaSCredential 不接收 context,插件无法
// 感知调用方的取消/超时,长时间挂起的插件调用会阻塞缓存刷新的 singleflight leader,
// 使所有 waiter 一起挂起。实现了本接口的插件会被优先使用 context 版本。
//
// 旧插件无需改动——SDK 通过类型断言检测,未实现本接口时回退到无 context 版本。
// 本接口为可选契约,不破坏 v0.x beta 的 API 兼容性。
type PluginCredentialProviderWithContext interface {
	GetIDaaSCredentialWithContext(ctx context.Context, scope string) (credential.IDaaSCredential, error)
}
