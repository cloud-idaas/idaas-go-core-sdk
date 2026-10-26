package factory

import (
	"context"

	"github.com/cloud-idaas/idaas-go-core-sdk/config"
	"github.com/cloud-idaas/idaas-go-core-sdk/constants"
	"github.com/cloud-idaas/idaas-go-core-sdk/errors"
	"github.com/cloud-idaas/idaas-go-core-sdk/logger"
	"github.com/cloud-idaas/idaas-go-core-sdk/provider"
)

// Init 从配置文件路径初始化工厂。
//
// configPaths 可变参数:
// - 不传:走 LoadWithPriority 三级优先级链(env var CLOUD_IDAAS_CONFIG_PATH →
// 默认路径 ~/.cloud_idaas/client-config.json)。独立环境变量兜底已移除,
// 需要从环境变量加载请显式调用 config.LoadFromEnv()
// - 传一个:作为显式文件路径传入 LoadWithPriority (硬失败,不静默回退)
// - 传多个:按顺序尝试 LoadFromFile,第一个成功加载的生效;
// 全部失败则走 LoadWithPriority("") 兜底
//
// 幂等:已初始化时记录 INFO 并直接返回 nil。
// 预热:初始化末尾为默认 scope 建 provider 并触发一次 GetCredential。
func Init(configPaths ...string) error {
	// 先检查已初始化状态,再读取配置文件:若工厂已初始化且配置文件随后被删除,
	// 重复 Init(samePath) 必须幂等返回 nil 而非加载错误。并发首次初始化路径仍走
	// Initialize 的双重检查。
	f := GetInstance()
	if f.IsInitialized() {
		logger.Default().Info(context.Background(),
			"factory already initialized, skipping",
			"event", "factory.init", "status", "idempotent_skip")
		return nil
	}

	reader := config.NewConfigReader()
	var cfg *config.IDaaSClientConfig
	var err error

	switch len(configPaths) {
	case 0:
		// 无显式路径:走全量优先级链
		cfg, err = reader.LoadWithPriority("")
	case 1:
		// 单路径:显式传入,硬失败
		cfg, err = reader.LoadWithPriority(configPaths[0])
	default:
		// 多路径:按顺序尝试,第一个成功生效;全失败则走优先级链兜底
		for _, p := range configPaths {
			cfg, err = reader.LoadFromFile(p)
			if err == nil {
				break
			}
		}
		if cfg == nil {
			cfg, err = reader.LoadWithPriority("")
		}
	}

	if err != nil {
		return errors.NewConfigError(constants.ClientConfigurationNotFound, "failed to load config", err)
	}
	return f.Initialize(cfg)
}

// InitWithConfig 从已构造的 *IDaaSClientConfig 初始化工厂。
//
// 适用于宿主应用自行从非文件来源(如 KMS、配置中心)组装配置的场景。
// 幂等:已初始化时直接返回 nil。
func InitWithConfig(cfg *config.IDaaSClientConfig) error {
	return GetInstance().Initialize(cfg)
}

// GetIDaaSCredentialProvider 获取默认 scope 的凭证提供者。
//
// 使用配置中的 Scope 字段作为 scope。如果 Scope 为空,使用空字符串
// (machine provider 会用默认 scope 处理)。
func GetIDaaSCredentialProvider() (provider.IDaaSCredentialProvider, error) {
	f := GetInstance()
	if !f.IsInitialized() {
		return nil, errors.NewConfigError(constants.IDaaSCredentialProviderFactoryNotInit, "Factory not initialized, call factory.Init() first", nil)
	}
	scope := ""
	if cfg := f.GetConfig(); cfg != nil {
		scope = cfg.Scope
	}
	return f.GetIDaaSCredentialProviderByScope(scope)
}

// GetIDaaSCredentialProviderByScope 获取指定 scope 的凭证提供者。
//
// scope 经 CanonicalizeScope 规范化后作为缓存键的一部分。
// 同一 scope 的多次调用返回同一个 provider 实例(带缓存)。
func GetIDaaSCredentialProviderByScope(scope string) (provider.IDaaSCredentialProvider, error) {
	return GetInstance().GetIDaaSCredentialProviderByScope(scope)
}

// GetIDaaSTokenExchangeCredentialProvider 获取默认 scope 的令牌交换提供者。
func GetIDaaSTokenExchangeCredentialProvider() (provider.IDaaSTokenExchangeCredentialProvider, error) {
	f := GetInstance()
	if !f.IsInitialized() {
		return nil, errors.NewConfigError(constants.IDaaSCredentialProviderFactoryNotInit, "Factory not initialized, call factory.Init() first", nil)
	}
	scope := ""
	if cfg := f.GetConfig(); cfg != nil {
		scope = cfg.Scope
	}
	return f.GetIDaaSTokenExchangeCredentialProviderByScope(scope)
}

// GetIDaaSTokenExchangeCredentialProviderByScope 获取指定 scope 的令牌交换提供者。
func GetIDaaSTokenExchangeCredentialProviderByScope(scope string) (provider.IDaaSTokenExchangeCredentialProvider, error) {
	return GetInstance().GetIDaaSTokenExchangeCredentialProviderByScope(scope)
}

// GetDeveloperApiEndpoint 返回 Developer API 端点。
//
// 未初始化时返回空字符串。
func GetDeveloperApiEndpoint() string {
	return GetInstance().GetDeveloperApiEndpoint()
}

// GetOpenApiEndpoint 返回 OpenAPI 端点。
func GetOpenApiEndpoint() string {
	return GetInstance().GetOpenApiEndpoint()
}

// GetIDaaSInstanceId 返回实例 ID。
func GetIDaaSInstanceId() string {
	return GetInstance().GetIDaaSInstanceId()
}

// GetClientId 返回 Client ID。
func GetClientId() string {
	return GetInstance().GetClientId()
}

// GetHttpConfig 返回 HTTP 配置的深拷贝。
//
// 返回深拷贝以防止调用方就地修改影响已冻结的配置快照。
// 未配置 HttpConfiguration 时返回 nil。
func GetHttpConfig() *config.HttpConfiguration {
	return GetInstance().GetHttpConfig()
}

// Reset 重置工厂状态。
//
// 清除所有 provider 缓存和初始化状态,使下一次 Init 可以用新配置重新初始化。
// 仅供测试 / CLI 场景使用。
func Reset() {
	GetInstance().Reset()
}
