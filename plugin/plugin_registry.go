package plugin

import (
	"sync"

	"github.com/aliyun/idaas-go-core-sdk/errors"
	"github.com/aliyun/idaas-go-core-sdk/provider"
)

// PluginRegistry 插件注册表
// 使用全局注册模式，等价于 Java SDK 的 PluginCredentialProviderUtil
type PluginRegistry struct {
	mu      sync.RWMutex
	plugins map[string]provider.PluginCredentialProvider
}

var (
	registryInstance *PluginRegistry
	registryOnce     sync.Once
	resetMu          sync.Mutex // 保护 ResetForTesting 对单例的重置，避免并行测试下的 data race
)

// GetInstance 获取单例注册表实例
func GetInstance() *PluginRegistry {
	registryOnce.Do(func() {
		registryInstance = &PluginRegistry{
			plugins: make(map[string]provider.PluginCredentialProvider),
		}
	})
	return registryInstance
}

// Register 注册插件（名称从 plugin.GetName() 自动获取，与 Java SPI 行为对齐）
func (r *PluginRegistry) Register(p provider.PluginCredentialProvider) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	name := p.GetName()
	if name == "" {
		return errors.NewConfigError("PluginNameEmpty", "Plugin GetName() returned empty string", nil)
	}
	if _, exists := r.plugins[name]; exists {
		return errors.NewConfigError("PluginAlreadyRegistered", "Plugin already registered: "+name, nil)
	}

	r.plugins[name] = p
	return nil
}

// GetPlugin 按名称获取插件
func (r *PluginRegistry) GetPlugin(name string) (provider.PluginCredentialProvider, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	p, ok := r.plugins[name]
	if !ok {
		return nil, errors.NewConfigError("PluginNotFound", "Plugin not found: "+name, nil)
	}

	return p, nil
}

// Unregister 注销插件
func (r *PluginRegistry) Unregister(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.plugins[name]; !exists {
		return errors.NewConfigError("PluginNotFound", "Plugin not found: "+name, nil)
	}

	delete(r.plugins, name)
	return nil
}

// ResetForTesting 重置注册表状态（仅用于单元测试）
//
// 警告：此方法会清除所有已注册插件并重置单例，生产环境禁止调用。
func ResetForTesting() {
	resetMu.Lock()
	defer resetMu.Unlock()
	registryOnce = sync.Once{}
	registryInstance = nil
}
