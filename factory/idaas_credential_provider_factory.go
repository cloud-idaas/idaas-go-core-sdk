package factory

import (
	"sync"

	"github.com/aliyun/idaas-go-core-sdk/config"
	"github.com/aliyun/idaas-go-core-sdk/constants"
	"github.com/aliyun/idaas-go-core-sdk/enums"
	"github.com/aliyun/idaas-go-core-sdk/errors"
	"github.com/aliyun/idaas-go-core-sdk/http"
	"github.com/aliyun/idaas-go-core-sdk/implementation"
	"github.com/aliyun/idaas-go-core-sdk/implementation/authentication"
	"github.com/aliyun/idaas-go-core-sdk/provider"
)

// IDaaSCredentialProviderFactory 凭证提供者工厂 (§4.1)
type IDaaSCredentialProviderFactory struct {
	mu          sync.RWMutex
	initialized bool
	providers   map[string]provider.IDaaSCredentialProvider
	config      *config.IDaaSClientConfig
	httpClient  http.HttpClient
}

var (
	factoryInstance *IDaaSCredentialProviderFactory
	factoryOnce     sync.Once
)

// GetInstance 获取单例工厂实例
func GetInstance() *IDaaSCredentialProviderFactory {
	factoryOnce.Do(func() {
		factoryInstance = &IDaaSCredentialProviderFactory{
			providers: make(map[string]provider.IDaaSCredentialProvider),
		}
	})
	return factoryInstance
}

// Initialize 初始化工厂 (§4.1)。
//
// Initialize 可重复调用；每次调用都会使用新配置重建 HTTP client 并清空 provider 缓存，
// 避免 CLI/测试/多租户场景中旧配置污染后续调用。
func (f *IDaaSCredentialProviderFactory) Initialize(cfg *config.IDaaSClientConfig) error {
	validator := config.NewConfigValidator()
	if err := validator.Validate(cfg); err != nil {
		return err
	}

	var httpClient http.HttpClient
	if cfg.HttpConfiguration != nil {
		httpClient = http.NewDefaultHttpClientWithOptions(
			cfg.HttpConfiguration.ConnectTimeout,
			cfg.HttpConfiguration.ReadTimeout,
			cfg.HttpConfiguration.UnsafeIgnoreSSLCert,
		)
	} else {
		httpClient = http.NewDefaultHttpClient(0, 0)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	f.config = cfg
	f.httpClient = httpClient
	f.providers = make(map[string]provider.IDaaSCredentialProvider)
	f.initialized = true

	return nil
}

// CreateCredentialProvider 创建凭证提供者 (§4.1)。
func (f *IDaaSCredentialProviderFactory) CreateCredentialProvider() (provider.IDaaSCredentialProvider, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if !f.initialized {
		return nil, errors.NewConfigError("FactoryNotInitialized", "Factory not initialized", nil)
	}

	cacheKey := f.config.InstanceId + ":" + f.config.ClientId
	if existing, ok := f.providers[cacheKey]; ok {
		return existing, nil
	}

	var newProvider provider.IDaaSCredentialProvider
	var err error
	switch f.config.AuthnConfiguration.IdentityType {
	case enums.AuthenticationIdentityClient:
		newProvider, err = f.createMachineProvider()
	case enums.AuthenticationIdentityHuman:
		newProvider, err = f.createHumanProvider()
	default:
		return nil, errors.NewConfigError("UnsupportedIdentityType", "Unsupported identity type", nil)
	}
	if err != nil {
		return nil, err
	}

	f.providers[cacheKey] = newProvider
	return newProvider, nil
}

// createMachineProvider 创建机器凭证提供者
func (f *IDaaSCredentialProviderFactory) createMachineProvider() (provider.IDaaSCredentialProvider, error) {
	return implementation.NewIDaaSMachineCredentialProvider(f.config, f.httpClient), nil
}

// createHumanProvider 创建人类凭证提供者
func (f *IDaaSCredentialProviderFactory) createHumanProvider() (provider.IDaaSCredentialProvider, error) {
	// 人类凭证使用 Device Code 流程
	if f.config.DeviceAuthorizationEndpoint == "" {
		return nil, errors.NewConfigError("DeviceAuthorizationEndpointNotFound", "Device authorization endpoint is required for human authentication", nil)
	}

	humanClientId := f.config.AuthnConfiguration.HumanAuthenticateClientId
	if humanClientId == "" {
		// 使用默认值，与 Java SDK 保持一致
		humanClientId = constants.DefaultHumanAuthenticateClientId
	}

	// 创建 Human Federated OIDC Token Provider
	humanProvider := authentication.NewHumanFederatedOidcTokenProvider(
		humanClientId,
		f.config.TokenEndpoint,
		f.config.DeviceAuthorizationEndpoint,
		f.httpClient,
	)

	return humanProvider, nil
}

// IsInitialized 检查是否已初始化
func (f *IDaaSCredentialProviderFactory) IsInitialized() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.initialized
}

// GetConfig 返回当前配置（供插件读取 instanceId / clientId / openApiEndpoint 等）
// 与 Java SDK IDaaSCredentialProviderFactory.getIDaasInstanceId() / getClientId() / getOpenApiEndpoint() 对齐
func (f *IDaaSCredentialProviderFactory) GetConfig() *config.IDaaSClientConfig {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.config
}
