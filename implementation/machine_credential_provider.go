package implementation

import (
	"os"
	"time"

	"github.com/aliyun/idaas-go-core-sdk/cache"
	"github.com/aliyun/idaas-go-core-sdk/config"
	"github.com/aliyun/idaas-go-core-sdk/constants"
	"github.com/aliyun/idaas-go-core-sdk/credential"
	"github.com/aliyun/idaas-go-core-sdk/enums"
	"github.com/aliyun/idaas-go-core-sdk/errors"
	"github.com/aliyun/idaas-go-core-sdk/http"
	"github.com/aliyun/idaas-go-core-sdk/implementation/authentication"
	"github.com/aliyun/idaas-go-core-sdk/oauth2"
	"github.com/aliyun/idaas-go-core-sdk/plugin"
	"github.com/aliyun/idaas-go-core-sdk/provider"
	"github.com/aliyun/idaas-go-core-sdk/util"
)

// IDaaSMachineCredentialProvider 机器凭证提供者 (§2.1 Layer3)
// 支持 8 种认证方式的 switch
type IDaaSMachineCredentialProvider struct {
	*AbstractRefreshedCredentialProvider
	config     *config.IDaaSClientConfig
	httpClient http.HttpClient
}

// NewIDaaSMachineCredentialProvider 创建 IDaaSMachineCredentialProvider
func NewIDaaSMachineCredentialProvider(
	cfg *config.IDaaSClientConfig,
	httpClient http.HttpClient,
) *IDaaSMachineCredentialProvider {
	provider := &IDaaSMachineCredentialProvider{
		config:     cfg,
		httpClient: httpClient,
	}

	// 创建刷新函数
	refreshFunc := func() (*cache.RefreshResult[credential.IDaaSCredential], error) {
		cred, err := provider.refreshCredential()
		if err != nil {
			return nil, err
		}
		return &cache.RefreshResult[credential.IDaaSCredential]{
			Value:     cred,
			ExpiresAt: time.Now().Add(time.Duration(cred.GetExpiresIn()) * time.Second),
		}, nil
	}

	provider.AbstractRefreshedCredentialProvider = NewAbstractRefreshedCredentialProvider(
		refreshFunc,
		enums.StaleValueBehaviorRefresh,
		5*time.Minute,
	)

	return provider
}

// refreshCredential 根据 authn_method 刷新凭证
func (p *IDaaSMachineCredentialProvider) refreshCredential() (credential.IDaaSCredential, error) {
	if p.config.AuthnConfiguration == nil {
		return nil, errors.NewConfigError("AuthnConfigurationNotFound", "Authn configuration is required", nil)
	}

	switch p.config.AuthnConfiguration.AuthnMethod {
	case enums.TokenAuthnMethodClientSecretBasic,
		enums.TokenAuthnMethodClientSecretPost,
		enums.TokenAuthnMethodClientSecretJwt:
		return p.getClientSecretCredential()
	case enums.TokenAuthnMethodPrivateKeyJwt:
		return p.getPrivateKeyJwtCredential()
	case enums.TokenAuthnMethodPCA:
		return p.getPcaCredential()
	case enums.TokenAuthnMethodPkcs7:
		return p.getPkcs7Credential()
	case enums.TokenAuthnMethodOidc:
		return p.getOidcCredential()
	case enums.TokenAuthnMethodPlugin:
		return p.getPluginCredential()
	default:
		return nil, errors.NewClientError("UnsupportedAuthenticationMethod", "Unsupported authn method: "+string(p.config.AuthnConfiguration.AuthnMethod), nil)
	}
}

// loadPrivateKeyFromEnv 从环境变量加载 PEM 私钥，供 getPcaCredential / getPrivateKeyJwtCredential 共用
func (p *IDaaSMachineCredentialProvider) loadPrivateKeyFromEnv(authnMethodLabel string) (interface{}, error) {
	authnConf := p.config.AuthnConfiguration
	if authnConf.PrivateKeyEnvVarName == "" {
		return nil, errors.NewConfigError(
			"PrivateKeyEnvVarNameNotFound",
			"privateKeyEnvVarName is required for "+authnMethodLabel,
			nil,
		)
	}
	privateKeyDataStr := os.Getenv(authnConf.PrivateKeyEnvVarName)
	if privateKeyDataStr == "" {
		return nil, errors.NewConfigError(
			"PrivateKeyNotFound",
			"Private key not found in environment variable: "+authnConf.PrivateKeyEnvVarName,
			nil,
		)
	}
	pemBytes, err := util.LoadPrivateKeyMaterial(privateKeyDataStr)
	if err != nil {
		return nil, errors.NewConfigError(
			"PrivateKeyInvalid",
			"Invalid private key from env var "+authnConf.PrivateKeyEnvVarName+": "+err.Error(),
			err,
		)
	}
	privateKey, err := util.ParsePrivateKeyFromPEM(pemBytes)
	if err != nil {
		return nil, errors.NewConfigError(
			"PrivateKeyInvalid",
			"Failed to parse private key from env var "+authnConf.PrivateKeyEnvVarName+": "+err.Error(),
			err,
		)
	}
	return privateKey, nil
}

// getPcaCredential 获取 PCA (Private CA) X509 证书凭证
//
// 与 Java SDK IDaaSMachineCredentialProvider.case PCA 完全对齐：
//   - 复用 StaticX509AssertionProvider 构造 JWT assertion（iss=sub=clientId）
//   - 调用 OAuth2TokenUtil.GetTokenByX509JwtBearer 发送 token 请求
//   - 必填配置：privateKeyEnvVarName、clientX509Certificate、x509CertChains、applicationFederatedCredentialName
func (p *IDaaSMachineCredentialProvider) getPcaCredential() (credential.IDaaSCredential, error) {
	authnConf := p.config.AuthnConfiguration
	privateKey, err := p.loadPrivateKeyFromEnv("pca")
	if err != nil {
		return nil, err
	}

	if authnConf.ApplicationFederatedCredentialName == "" {
		return nil, errors.NewConfigError(
			"ApplicationFederatedCredentialNameNotFound",
			"applicationFederatedCredentialName is required for PCA authentication",
			nil,
		)
	}
	if authnConf.ClientX509Certificate == "" {
		return nil, errors.NewConfigError(
			"ClientX509CertificateNotFound",
			"clientX509Certificate (leaf certificate PEM) is required for PCA authentication",
			nil,
		)
	}
	if authnConf.X509CertChains == "" {
		return nil, errors.NewConfigError(
			"X509CertChainsNotFound",
			"x509CertChains (intermediate certificate chain PEM) is required for PCA authentication",
			nil,
		)
	}

	provider := authentication.NewStaticX509AssertionProvider(
		p.config.ClientId,
		privateKey,
		authnConf.ClientX509Certificate,
		authnConf.X509CertChains,
		authnConf.ApplicationFederatedCredentialName,
		p.config.TokenEndpoint,
		p.config.Scope,
		p.httpClient,
	)
	return provider.GetCredential()
}

// getClientSecretCredential 获取 Client Secret 凭证
func (p *IDaaSMachineCredentialProvider) getClientSecretCredential() (credential.IDaaSCredential, error) {
	clientSecret := os.Getenv(p.config.AuthnConfiguration.ClientSecretEnvVarName)
	if clientSecret == "" {
		return nil, errors.NewConfigError("ClientSecretNotFound", "Client secret not found in environment variable: "+p.config.AuthnConfiguration.ClientSecretEnvVarName, nil)
	}

	provider := authentication.NewStaticClientSecretAssertionProvider(
		p.config.ClientId,
		clientSecret,
		p.config.TokenEndpoint,
		p.config.Scope,
		p.config.AuthnConfiguration.AuthnMethod,
		p.httpClient,
	)
	return provider.GetCredential()
}

// getPrivateKeyJwtCredential 获取 Private Key JWT 凭证
func (p *IDaaSMachineCredentialProvider) getPrivateKeyJwtCredential() (credential.IDaaSCredential, error) {
	// 需要解析私钥并创建 JWT assertion
	if p.config.AuthnConfiguration.PrivateKeyEnvVarName == "" {
		return nil, errors.NewConfigError("PrivateKeyEnvVarNameNotFound", "Private key env var name not configured", nil)
	}

	privateKeyDataStr := os.Getenv(p.config.AuthnConfiguration.PrivateKeyEnvVarName)
	if privateKeyDataStr == "" {
		return nil, errors.NewConfigError("PrivateKeyNotFound", "Private key not found in environment variable: "+p.config.AuthnConfiguration.PrivateKeyEnvVarName, nil)
	}

	pemBytes, err := util.LoadPrivateKeyMaterial(privateKeyDataStr)
	if err != nil {
		return nil, errors.NewConfigError(
			"PrivateKeyInvalid",
			"Invalid private key from env var "+p.config.AuthnConfiguration.PrivateKeyEnvVarName+": "+err.Error(),
			err,
		)
	}

	privateKey, err := util.ParsePrivateKeyFromPEM(pemBytes)
	if err != nil {
		return nil, errors.NewConfigError(
			"PrivateKeyInvalid",
			"Failed to parse private key from env var "+p.config.AuthnConfiguration.PrivateKeyEnvVarName+": "+err.Error(),
			err,
		)
	}

	provider := authentication.NewStaticPrivateKeyAssertionProvider(
		p.config.ClientId,
		p.config.IssuerEndpoint,
		privateKey,
		p.config.TokenEndpoint,
		p.config.Scope,
		p.httpClient,
	)
	return provider.GetCredential()
}

// getPkcs7Credential 获取 PKCS7 联邦凭证（按 authnConfiguration.clientDeployEnvironment 路由到不同 attestation provider）
//
// 与 Java SDK IDaaSMachineCredentialProvider.case PKCS7 完全对齐。
func (p *IDaaSMachineCredentialProvider) getPkcs7Credential() (credential.IDaaSCredential, error) {
	return p.getPkcs7CredentialForDeployEnv(p.config.AuthnConfiguration.ClientDeployEnvironment)
}

// getPkcs7CredentialForDeployEnv 根据 deployEnv 路由到具体的 PKCS7 attestation provider
func (p *IDaaSMachineCredentialProvider) getPkcs7CredentialForDeployEnv(deployEnv enums.ClientDeployEnvironmentEnum) (credential.IDaaSCredential, error) {
	authnConf := p.config.AuthnConfiguration
	if authnConf.ApplicationFederatedCredentialName == "" {
		return nil, errors.NewConfigError(
			"ApplicationFederatedCredentialNameNotFound",
			"applicationFederatedCredentialName is required for PKCS7 authentication",
			nil,
		)
	}

	tokenUtil := oauth2.NewOAuth2TokenUtil(p.httpClient)

	switch deployEnv {
	case enums.ClientDeployEnvironmentAlibabaCloudEcs:
		ecsProvider := authentication.NewAlibabaCloudEcsAttestedDocumentProvider(
			p.httpClient,
			p.config.InstanceId,
			0, // 使用默认 TTL 3600s
		)
		attestedDoc, err := ecsProvider.GetAttestedDocument()
		if err != nil {
			return nil, err
		}
		return tokenUtil.GetTokenWithPKCS7AttestedDocument(
			p.config.TokenEndpoint,
			p.config.ClientId,
			authnConf.ApplicationFederatedCredentialName,
			attestedDoc,
			p.config.Scope,
		)

	case enums.ClientDeployEnvironmentAwsEc2:
		ec2Provider := authentication.NewAwsEc2AttestedDocumentProvider(p.httpClient, 0)
		attestedDoc, err := ec2Provider.GetAttestedDocument()
		if err != nil {
			return nil, err
		}
		return tokenUtil.GetTokenWithPKCS7AttestedDocument(
			p.config.TokenEndpoint,
			p.config.ClientId,
			authnConf.ApplicationFederatedCredentialName,
			attestedDoc,
			p.config.Scope,
		)

	default:
		return nil, errors.NewConfigError(
			"UnsupportedClientDeployEnvironment",
			"Unsupported clientDeployEnvironment for PKCS7 authentication: "+string(deployEnv)+
				" (currently only ALIBABA_CLOUD_ECS and AWS_EC2 are implemented)",
			nil,
		)
	}
}

// getOidcCredential 获取 OIDC 联邦凭证（按 authnConfiguration.clientDeployEnvironment 路由到不同 oidc token provider）
//
// 与 Java SDK IDaaSMachineCredentialProvider.case OIDC 完全对齐。
func (p *IDaaSMachineCredentialProvider) getOidcCredential() (credential.IDaaSCredential, error) {
	return p.getOidcCredentialForDeployEnv(p.config.AuthnConfiguration.ClientDeployEnvironment)
}

// getOidcCredentialForDeployEnv 根据 deployEnv 路由到具体的 OIDC token provider
func (p *IDaaSMachineCredentialProvider) getOidcCredentialForDeployEnv(deployEnv enums.ClientDeployEnvironmentEnum) (credential.IDaaSCredential, error) {
	authnConf := p.config.AuthnConfiguration
	if authnConf.ApplicationFederatedCredentialName == "" {
		return nil, errors.NewConfigError(
			"ApplicationFederatedCredentialNameNotFound",
			"applicationFederatedCredentialName is required for OIDC authentication",
			nil,
		)
	}

	var oidcTokenProvider provider.OidcTokenProvider
	switch deployEnv {
	case enums.ClientDeployEnvironmentKubernetes:
		tokenPath := authnConf.OidcTokenFilePath
		if tokenPath == "" && authnConf.OidcTokenFilePathEnvVarName != "" {
			tokenPath = os.Getenv(authnConf.OidcTokenFilePathEnvVarName)
		}
		if tokenPath == "" {
			tokenPath = constants.K8sServiceAccountTokenPath
		}
		oidcTokenProvider = authentication.NewFileOidcTokenProvider(tokenPath)
	case enums.ClientDeployEnvironmentGoogleVm:
		// GCP VM OIDC：从元数据服务获取 ID Token
		// audience 取 issuer 的 origin（scheme://host[:port]），与 IDaaS 联邦凭证侧约定一致
		if p.config.IssuerEndpoint == "" {
			return nil, errors.NewConfigError(
				"IssuerEndpointNotFound",
				"issuer endpoint is required as audience source for GCP VM OIDC authentication",
				nil,
			)
		}
		audience, err := util.ExtractUrlOrigin(p.config.IssuerEndpoint)
		if err != nil {
			return nil, errors.NewConfigError(
				"IssuerEndpointInvalid",
				"failed to extract origin from issuer endpoint for GCP VM OIDC audience: "+err.Error(),
				err,
			)
		}
		oidcTokenProvider = authentication.NewGcpVmOidcTokenProvider(p.httpClient, audience)
	case enums.ClientDeployEnvironmentAzureVm:
		// Azure VM OIDC：从 IMDS Managed Identity 获取 ID Token
		// resource 取 issuer 的 origin（scheme://host[:port]），写入 token 的 aud claim
		if p.config.IssuerEndpoint == "" {
			return nil, errors.NewConfigError(
				"IssuerEndpointNotFound",
				"issuer endpoint is required as resource source for Azure VM OIDC authentication",
				nil,
			)
		}
		resource, err := util.ExtractUrlOrigin(p.config.IssuerEndpoint)
		if err != nil {
			return nil, errors.NewConfigError(
				"IssuerEndpointInvalid",
				"failed to extract origin from issuer endpoint for Azure VM OIDC resource: "+err.Error(),
				err,
			)
		}
		oidcTokenProvider = authentication.NewAzureVmOidcTokenProvider(p.httpClient, resource)
	default:
		return nil, errors.NewConfigError(
			"UnsupportedClientDeployEnvironment",
			"Unsupported clientDeployEnvironment for OIDC authentication: "+string(deployEnv)+
				" (currently only KUBERNETES, GOOGLE_VM and AZURE_VM are implemented)",
			nil,
		)
	}

	oidcToken, err := oidcTokenProvider.GetOidcToken()
	if err != nil {
		return nil, err
	}

	tokenUtil := oauth2.NewOAuth2TokenUtil(p.httpClient)
	tokenResp, err := tokenUtil.GetTokenWithOIDCFederatedCredential(
		p.config.TokenEndpoint,
		p.config.ClientId,
		authnConf.ApplicationFederatedCredentialName,
		oidcToken,
		p.config.Scope,
	)
	if err != nil {
		return nil, err
	}
	return tokenResp, nil
}

// getPluginCredential 通过插件获取凭证
// 与 Java SDK OAuth2TokenUtil.getTokenWithPlugin() 对齐：
// 直接委托给插件实现，SDK 不发起 HTTP 请求
func (p *IDaaSMachineCredentialProvider) getPluginCredential() (credential.IDaaSCredential, error) {
	pluginName := p.config.AuthnConfiguration.PluginName

	registry := plugin.GetInstance()
	pluginProvider, err := registry.GetPlugin(pluginName)
	if err != nil {
		return nil, err
	}

	return pluginProvider.GetIDaaSCredential(p.config.Scope)
}
