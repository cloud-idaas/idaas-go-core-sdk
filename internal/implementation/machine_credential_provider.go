package implementation

import (
	"context"
	"time"

	"github.com/cloud-idaas/idaas-go-core-sdk/cache"
	"github.com/cloud-idaas/idaas-go-core-sdk/config"
	"github.com/cloud-idaas/idaas-go-core-sdk/constants"
	"github.com/cloud-idaas/idaas-go-core-sdk/credential"
	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
	"github.com/cloud-idaas/idaas-go-core-sdk/errors"
	"github.com/cloud-idaas/idaas-go-core-sdk/http"
	"github.com/cloud-idaas/idaas-go-core-sdk/internal/implementation/authentication"
	"github.com/cloud-idaas/idaas-go-core-sdk/oauth2"
	"github.com/cloud-idaas/idaas-go-core-sdk/plugin"
	"github.com/cloud-idaas/idaas-go-core-sdk/provider"
)

// IDaaSMachineCredentialProvider 机器凭证提供者 ( Layer3)
// 支持 8 种认证方式的 switch
type IDaaSMachineCredentialProvider struct {
	*AbstractRefreshedCredentialProvider
	config     *config.IDaaSClientConfig
	httpClient http.HttpClient
	// scope 构造时绑定、之后不变，所有 grant 都发送它。
	// 不读 config.Scope：factory 按 scope 为每个 scope 各建一个 provider，共享同一份 config。
	scope string
}

// NewIDaaSMachineCredentialProvider 创建使用 cfg.Scope 的 IDaaSMachineCredentialProvider。
func NewIDaaSMachineCredentialProvider(
	cfg *config.IDaaSClientConfig,
	staleBehavior enums.StaleValueBehavior,
	httpClient http.HttpClient,
) *IDaaSMachineCredentialProvider {
	return NewIDaaSMachineCredentialProviderForScope(cfg, cfg.Scope, staleBehavior, httpClient)
}

// NewIDaaSMachineCredentialProviderForScope 创建向 token endpoint 请求指定 scope 的
// IDaaSMachineCredentialProvider。
func NewIDaaSMachineCredentialProviderForScope(
	cfg *config.IDaaSClientConfig,
	scope string,
	staleBehavior enums.StaleValueBehavior,
	httpClient http.HttpClient,
) *IDaaSMachineCredentialProvider {
	mcp := &IDaaSMachineCredentialProvider{
		config:     cfg,
		httpClient: httpClient,
		scope:      scope,
	}

	// 创建刷新函数 (使用 NewRefreshResult 自动计算 StaleTime/PrefetchTime)
	// refreshFunc 带 ctx:ctx 透传到刷新链路,支持请求级取消。
	refreshFunc := func(ctx context.Context) (*cache.RefreshResult[credential.IDaaSCredential], error) {
		cred, err := mcp.refreshCredential(ctx)
		if err != nil {
			return nil, err
		}
		// 计算缓存过期时间时使用凭证的真实接收时间(ReceivedAt)而非零值:
		// 零值会使 NewRefreshResult 回退到 GetClock().Now(),对于 PLUGIN 等可能返回
		// 内部已缓存凭证的 authn 方式,会将 full TTL from now 作为有效期,导致
		// 过期 token 被缓存最长达整个 token 生命周期。
		receivedAt := time.Time{}
		if tr, ok := cred.(*credential.IDaaSTokenResponse); ok && !tr.ReceivedAt.IsZero() {
			receivedAt = tr.ReceivedAt
		}
		expiresIn := cred.GetExpiresIn()
		// 对于不暴露 ReceivedAt 的 PLUGIN 凭证(插件返回的自定义凭证类型,
		// remaining lifetime 未知),不应用完整 TTL 缓存。使用保守短 TTL(上限 60s),
		// 近乎 pass-through,避免缓存过期 token 最长达整个 token 生命周期。
		// 取 min(expiresIn, 60):expiresIn 为 0 时取 60(保守默认),否则取较小值。
		// 无条件覆盖为 60 会让仅剩 20s 的插件令牌被缓存 60s → 过期 40s。
		if receivedAt.IsZero() && cfg.AuthnConfiguration.AuthnMethod == enums.TokenAuthnMethodPlugin {
			if expiresIn == 0 || expiresIn > 60 {
				expiresIn = 60
			}
		}
		result, err := cache.NewRefreshResult[credential.IDaaSCredential](cred, receivedAt, expiresIn)
		if err != nil {
			return nil, err
		}
		return &result, nil
	}

	mcp.AbstractRefreshedCredentialProvider = NewAbstractRefreshedCredentialProvider(
		refreshFunc,
		staleBehavior,
	)
	// 设置 scope 使 RefreshEvent 能携带 scope 信息。
	mcp.SetScope(scope)

	return mcp
}

// refreshCredential 根据 authn_method 刷新凭证 (ctx 透传到刷新链路)
func (p *IDaaSMachineCredentialProvider) refreshCredential(ctx context.Context) (credential.IDaaSCredential, error) {
	if p.config.AuthnConfiguration == nil {
		return nil, errors.NewConfigError(constants.AuthnConfigurationNotFound, "Authn configuration is required", nil)
	}

	switch p.config.AuthnConfiguration.AuthnMethod {
	case enums.TokenAuthnMethodClientSecretBasic,
		enums.TokenAuthnMethodClientSecretPost,
		enums.TokenAuthnMethodClientSecretJwt:
		return p.getClientSecretCredential(ctx)
	case enums.TokenAuthnMethodPrivateKeyJwt:
		return p.getPrivateKeyJwtCredential(ctx)
	case enums.TokenAuthnMethodPca:
		return p.getPcaCredential(ctx)
	case enums.TokenAuthnMethodPkcs7:
		return p.getPkcs7Credential(ctx)
	case enums.TokenAuthnMethodOidc:
		return p.getOidcCredential(ctx)
	case enums.TokenAuthnMethodPlugin:
		return p.getPluginCredential(ctx)
	default:
		return nil, errors.NewClientError(constants.UnsupportedAuthenticationMethod, "Unsupported authn method: "+string(p.config.AuthnConfiguration.AuthnMethod), nil)
	}
}

// loadPrivateKeyFromEnv 从环境变量加载 PEM 私钥，供 getPcaCredential / getPrivateKeyJwtCredential 共用
func (p *IDaaSMachineCredentialProvider) loadPrivateKeyFromEnv(authnMethodLabel string) (interface{}, error) {
	return loadClientPrivateKey(p.config, authnMethodLabel)
}

// getPcaCredential 获取 PCA (Private CA) X509 证书凭证
//
// 与 Java SDK IDaaSMachineCredentialProvider.case PCA 完全对齐：
// - 复用 StaticX509AssertionProvider 构造 JWT assertion（iss=sub=clientId）
// - 调用 OAuth2TokenUtil.GetTokenByX509JwtBearer 发送 token 请求
// - 必填配置：privateKeyEnvVarName、clientX509Certificate、x509CertChains、applicationFederatedCredentialName
func (p *IDaaSMachineCredentialProvider) getPcaCredential(ctx context.Context) (credential.IDaaSCredential, error) {
	authnConf := p.config.AuthnConfiguration
	privateKey, err := p.loadPrivateKeyFromEnv("pca")
	if err != nil {
		return nil, err
	}

	// 配置必填项（applicationFederatedCredentialName / clientX509Certificate / x509CertChains）
	// 已在 config.ConfigValidator.Validate 中校验，此处不再重复。
	// provider 侧只保留运行期才能知道的检查：环境变量取值与私钥解析（已在 loadPrivateKeyFromEnv 中完成）。

	x509Provider := authentication.NewStaticX509AssertionProvider(
		p.config.ClientId,
		privateKey,
		authnConf.ClientX509Certificate,
		authnConf.X509CertChains,
		authnConf.ApplicationFederatedCredentialName,
		p.config.TokenEndpoint,
		p.scope,
		p.httpClient,
	)
	return x509Provider.GetCredentialWithContext(ctx)
}

// getClientSecretCredential 获取 Client Secret 凭证 (ctx 透传)
func (p *IDaaSMachineCredentialProvider) getClientSecretCredential(ctx context.Context) (credential.IDaaSCredential, error) {
	clientSecret, err := readClientSecret(p.config)
	if err != nil {
		return nil, err
	}

	secretProvider := authentication.NewStaticClientSecretAssertionProvider(
		p.config.ClientId,
		clientSecret,
		p.config.TokenEndpoint,
		p.scope,
		p.config.AuthnConfiguration.AuthnMethod,
		p.httpClient,
	)
	return secretProvider.GetCredentialWithContext(ctx)
}

// getPrivateKeyJwtCredential 获取 Private Key JWT 凭证 (ctx 透传)
//
// 复用 loadPrivateKeyFromEnv（与 getPcaCredential 共用），消除重复的环境变量读取 +
// PEM 解析逻辑 (DRY 修复)。
func (p *IDaaSMachineCredentialProvider) getPrivateKeyJwtCredential(ctx context.Context) (credential.IDaaSCredential, error) {
	privateKey, err := p.loadPrivateKeyFromEnv("private_key_jwt")
	if err != nil {
		return nil, err
	}

	keyProvider := authentication.NewStaticPrivateKeyAssertionProvider(
		p.config.ClientId,
		privateKey,
		p.config.TokenEndpoint,
		p.scope,
		p.httpClient,
	)
	return keyProvider.GetCredentialWithContext(ctx)
}

// getPkcs7Credential 获取 PKCS7 联邦凭证（按 authnConfiguration.clientDeployEnvironment 路由到不同 attestation provider）(ctx 透传)
//
// 与 Java SDK IDaaSMachineCredentialProvider.case PKCS7 完全对齐。
func (p *IDaaSMachineCredentialProvider) getPkcs7Credential(ctx context.Context) (credential.IDaaSCredential, error) {
	return p.getPkcs7CredentialForDeployEnv(ctx, p.config.AuthnConfiguration.ClientDeployEnvironment)
}

// getPkcs7CredentialForDeployEnv 根据 deployEnv 路由到具体的 PKCS7 attestation provider (ctx 透传)
func (p *IDaaSMachineCredentialProvider) getPkcs7CredentialForDeployEnv(ctx context.Context, deployEnv enums.ClientDeployEnvironmentEnum) (credential.IDaaSCredential, error) {
	attestedDoc, err := fetchPkcs7AttestedDocument(ctx, p.config, p.httpClient, deployEnv)
	if err != nil {
		return nil, err
	}
	return oauth2.NewOAuth2TokenUtil(p.httpClient).GetTokenWithPKCS7AttestedDocumentWithContext(
		ctx,
		p.config.TokenEndpoint,
		p.config.ClientId,
		p.config.AuthnConfiguration.ApplicationFederatedCredentialName,
		attestedDoc,
		p.scope,
	)
}

// getOidcCredential 获取 OIDC 联邦凭证（按 authnConfiguration.clientDeployEnvironment 路由到不同 oidc token provider）(ctx 透传)
//
// 与 Java SDK IDaaSMachineCredentialProvider.case OIDC 完全对齐。
func (p *IDaaSMachineCredentialProvider) getOidcCredential(ctx context.Context) (credential.IDaaSCredential, error) {
	return p.getOidcCredentialForDeployEnv(ctx, p.config.AuthnConfiguration.ClientDeployEnvironment)
}

// getOidcCredentialForDeployEnv 根据 deployEnv 路由到具体的 OIDC token provider (ctx 透传)
func (p *IDaaSMachineCredentialProvider) getOidcCredentialForDeployEnv(ctx context.Context, deployEnv enums.ClientDeployEnvironmentEnum) (credential.IDaaSCredential, error) {
	oidcToken, err := fetchOidcToken(ctx, p.config, p.httpClient, deployEnv)
	if err != nil {
		return nil, err
	}
	tokenResp, err := oauth2.NewOAuth2TokenUtil(p.httpClient).GetTokenWithOIDCFederatedCredentialWithContext(
		ctx,
		p.config.TokenEndpoint,
		p.config.ClientId,
		p.config.AuthnConfiguration.ApplicationFederatedCredentialName,
		oidcToken,
		p.scope,
	)
	if err != nil {
		return nil, err
	}
	return tokenResp, nil
}

// getPluginCredential 通过插件获取凭证 (ctx 透传到插件,支持取消/超时)
// 与 Java SDK OAuth2TokenUtil.getTokenWithPlugin() 对齐：
// 直接委托给插件实现，SDK 不发起 HTTP 请求
func (p *IDaaSMachineCredentialProvider) getPluginCredential(ctx context.Context) (credential.IDaaSCredential, error) {
	pluginName := p.config.AuthnConfiguration.PluginName
	// 查注册表前先校验 pluginName 非空（防御性：即使调用方绕过了 validator 也不会用空名查注册表）
	if pluginName == "" {
		return nil, errors.NewConfigError(constants.PluginNameNotFound, "pluginName is required for PLUGIN authentication", nil)
	}

	registry := plugin.GetInstance()
	pluginProvider, err := registry.GetPlugin(pluginName)
	if err != nil {
		return nil, err
	}

	// 优先使用 context 版本,使插件能响应调用方取消/超时;
	// 未实现 PluginCredentialProviderWithContext 的旧插件回退到无 ctx 版本。
	if withCtx, ok := pluginProvider.(provider.PluginCredentialProviderWithContext); ok {
		return withCtx.GetIDaaSCredentialWithContext(ctx, p.scope)
	}
	return pluginProvider.GetIDaaSCredential(p.scope)
}
