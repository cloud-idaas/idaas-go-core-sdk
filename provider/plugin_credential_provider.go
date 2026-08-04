package provider

import "github.com/cloud-idaas/idaas-go-core-sdk/credential"

// PluginCredentialProvider 插件凭证提供者接口
//
// 与 Java SDK com.cloud_idaas.core.provider.PluginCredentialProvider 对齐：
//   - GetName() 返回插件唯一名称，用于注册和按 pluginName 查找
//   - GetIDaaSCredential(scope) 由插件自行获取完整 token（SDK 不发起 HTTP 请求）
type PluginCredentialProvider interface {
	// GetName 返回插件唯一名称（对应配置中的 pluginName）
	GetName() string

	// GetIDaaSCredential 根据 scope 获取完整的 IDaaS 凭证
	// 插件自行负责与外部系统交互（如阿里云 EIAM OpenAPI），SDK 不参与
	GetIDaaSCredential(scope string) (credential.IDaaSCredential, error)
}
