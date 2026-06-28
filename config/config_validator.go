package config

import (
	"net/url"
	"strings"

	"github.com/aliyun/idaas-go-core-sdk/constants"
	"github.com/aliyun/idaas-go-core-sdk/enums"
	"github.com/aliyun/idaas-go-core-sdk/errors"
	"github.com/aliyun/idaas-go-core-sdk/util"
)

// ConfigValidator 配置验证器 (§8.5)
type ConfigValidator struct{}

// NewConfigValidator 创建 ConfigValidator
func NewConfigValidator() *ConfigValidator {
	return &ConfigValidator{}
}

// Validate 验证配置 (§8.5)
func (v *ConfigValidator) Validate(config *IDaaSClientConfig) error {
	// 验证必填字段
	if err := util.ValidateNotBlank(config.ClientId, "client_id"); err != nil {
		return errors.NewConfigError(constants.ClientIdNotFound, "Client ID is required", err)
	}

	if err := util.ValidateNotBlank(config.InstanceId, "instance_id"); err != nil {
		return errors.NewConfigError(constants.IDaaSInstanceIdNotFound, "Instance ID is required", err)
	}

	if err := util.ValidateNotBlank(config.IssuerEndpoint, "issuer_endpoint"); err != nil {
		return errors.NewConfigError(constants.IssuerEndpointNotFound, "Issuer endpoint is required", err)
	}
	if err := validateHttpUrl(config.IssuerEndpoint); err != nil {
		return errors.NewConfigError(constants.IssuerEndpointNotFound, "Issuer endpoint is not a valid URL: "+config.IssuerEndpoint, err)
	}

	if err := util.ValidateNotBlank(config.TokenEndpoint, "token_endpoint"); err != nil {
		return errors.NewConfigError(constants.TokenEndpointNotFound, "Token endpoint is required", err)
	}
	if err := validateHttpUrl(config.TokenEndpoint); err != nil {
		return errors.NewConfigError(constants.TokenEndpointNotFound, "Token endpoint is not a valid URL: "+config.TokenEndpoint, err)
	}

	// 验证 AuthnConfiguration
	if config.AuthnConfiguration == nil {
		return errors.NewConfigError(constants.AuthnConfigurationNotFound, "Authn configuration is required", nil)
	}

	// 根据 authn_method 验证对应的凭证（覆盖全部已支持的认证方式，确保配置错误能尽早暴露）
	switch config.AuthnConfiguration.AuthnMethod {
	case enums.TokenAuthnMethodClientSecretBasic, enums.TokenAuthnMethodClientSecretPost:
		if config.AuthnConfiguration.ClientSecretEnvVarName == "" {
			return errors.NewConfigError(constants.ClientSecretEnvVarNameNotFound, "Client secret env var name is required for client_secret authentication", nil)
		}
	case enums.TokenAuthnMethodClientSecretJwt:
		// client_secret_jwt 需要 client_secret 作为 HS256 签名密钥
		if config.AuthnConfiguration.ClientSecretEnvVarName == "" {
			return errors.NewConfigError(constants.ClientSecretEnvVarNameNotFound, "Client secret env var name is required for client_secret_jwt authentication", nil)
		}
	case enums.TokenAuthnMethodPrivateKeyJwt:
		if config.AuthnConfiguration.PrivateKeyEnvVarName == "" {
			return errors.NewConfigError(constants.PrivateKeyEnvVarNameNotFound, "Private key env var name is required for private_key_jwt authentication", nil)
		}
	case enums.TokenAuthnMethodPCA:
		// PCA (Private CA) 校验与 Java SDK ValidatorUtil 对齐：4 个字段全部必填
		if config.AuthnConfiguration.PrivateKeyEnvVarName == "" {
			return errors.NewConfigError(constants.PrivateKeyEnvVarNameNotFound, "Private key env var name is required for PCA authentication", nil)
		}
		if config.AuthnConfiguration.ApplicationFederatedCredentialName == "" {
			return errors.NewConfigError("ApplicationFederatedCredentialNameNotFound", "applicationFederatedCredentialName is required for PCA authentication", nil)
		}
		if config.AuthnConfiguration.ClientX509Certificate == "" {
			return errors.NewConfigError("ClientX509CertificateNotFound", "clientX509Certificate (leaf certificate PEM) is required for PCA authentication", nil)
		}
		if config.AuthnConfiguration.X509CertChains == "" {
			return errors.NewConfigError("X509CertChainsNotFound", "x509CertChains (intermediate certificate chain PEM) is required for PCA authentication", nil)
		}
	case enums.TokenAuthnMethodPkcs7:
		if config.AuthnConfiguration.ApplicationFederatedCredentialName == "" {
			return errors.NewConfigError("ApplicationFederatedCredentialNameNotFound", "applicationFederatedCredentialName is required for PKCS7 federated authentication", nil)
		}
		if err := validatePkcs7DeployEnvironment(config.AuthnConfiguration.ClientDeployEnvironment); err != nil {
			return err
		}
	case enums.TokenAuthnMethodOidc:
		if config.AuthnConfiguration.ApplicationFederatedCredentialName == "" {
			return errors.NewConfigError("ApplicationFederatedCredentialNameNotFound", "applicationFederatedCredentialName is required for OIDC federated authentication", nil)
		}
		if err := validateOidcDeployEnvironment(config); err != nil {
			return err
		}
	case enums.TokenAuthnMethodPlugin:
		if config.AuthnConfiguration.PluginName == "" {
			return errors.NewConfigError("PluginNameNotFound", "pluginName is required when authnMethod is plugin", nil)
		}
	case enums.TokenAuthnMethodNone:
		// public client，不需要客户端凭证
	case "":
		return errors.NewConfigError("AuthnMethodNotFound", "authnMethod is required in authnConfiguration", nil)
	default:
		return errors.NewConfigError("UnsupportedAuthenticationMethod", "Unsupported authnMethod: "+string(config.AuthnConfiguration.AuthnMethod), nil)
	}

	return nil
}

// validateHttpUrl 校验字符串是否为合法的 http(s) 绝对 URL（必须含 scheme 与 host），
// 避免把明显非法的 endpoint 配置拖到运行时才在 HTTP 请求阶段失败、报错难以定位。
func validateHttpUrl(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.NewConfigError("InvalidEndpointScheme", "endpoint must use http or https scheme", nil)
	}
	if u.Host == "" {
		return errors.NewConfigError("InvalidEndpointHost", "endpoint must contain a host", nil)
	}
	return nil
}

// supportedPkcs7DeployEnvironments PKCS7 认证当前已实现的部署环境白名单
// 与 implementation.IDaaSMachineCredentialProvider.getPkcs7CredentialForDeployEnv 的 switch 分支保持一致
var supportedPkcs7DeployEnvironments = map[enums.ClientDeployEnvironmentEnum]struct{}{
	enums.ClientDeployEnvironmentAlibabaCloudEcs: {},
	enums.ClientDeployEnvironmentAwsEc2:          {},
}

// supportedOidcDeployEnvironments OIDC 认证当前已实现的部署环境白名单
// 与 implementation.IDaaSMachineCredentialProvider.getOidcCredentialForDeployEnv 的 switch 分支保持一致
var supportedOidcDeployEnvironments = map[enums.ClientDeployEnvironmentEnum]struct{}{
	enums.ClientDeployEnvironmentKubernetes: {},
	enums.ClientDeployEnvironmentGoogleVm:   {},
	enums.ClientDeployEnvironmentAzureVm:    {},
}

// validatePkcs7DeployEnvironment 校验 PKCS7 认证的部署环境
//
// 校验规则：
//   - clientDeployEnvironment 必须显式提供（与 Java SDK 保持一致：PKCS7 必须明确指定运行环境）
//   - 取值必须在已实现的白名单内（当前为 ALIBABA_CLOUD_ECS / AWS_EC2）
func validatePkcs7DeployEnvironment(deployEnv enums.ClientDeployEnvironmentEnum) error {
	if deployEnv == "" {
		return errors.NewConfigError(
			"ClientDeployEnvironmentNotFound",
			"clientDeployEnvironment is required for PKCS7 authentication (supported: ALIBABA_CLOUD_ECS, AWS_EC2)",
			nil,
		)
	}
	if _, ok := supportedPkcs7DeployEnvironments[deployEnv]; !ok {
		return errors.NewConfigError(
			"UnsupportedClientDeployEnvironment",
			"Unsupported clientDeployEnvironment for PKCS7 authentication: "+string(deployEnv)+
				" (currently only ALIBABA_CLOUD_ECS and AWS_EC2 are implemented)",
			nil,
		)
	}
	return nil
}

// validateOidcDeployEnvironment 校验 OIDC 认证的部署环境及其依赖配置
//
// 校验规则：
//   - clientDeployEnvironment 必须显式提供
//   - 取值必须在已实现的白名单内（当前为 KUBERNETES / GOOGLE_VM）
//   - GOOGLE_VM：依赖 issuer endpoint 作为元数据服务请求的 audience（基础字段已在 Validate 入口处校验）
func validateOidcDeployEnvironment(config *IDaaSClientConfig) error {
	deployEnv := config.AuthnConfiguration.ClientDeployEnvironment
	if deployEnv == "" {
		return errors.NewConfigError(
			"ClientDeployEnvironmentNotFound",
			"clientDeployEnvironment is required for OIDC authentication (supported: KUBERNETES, GOOGLE_VM, AZURE_VM)",
			nil,
		)
	}
	if _, ok := supportedOidcDeployEnvironments[deployEnv]; !ok {
		return errors.NewConfigError(
			"UnsupportedClientDeployEnvironment",
			"Unsupported clientDeployEnvironment for OIDC authentication: "+string(deployEnv)+
				" (currently only KUBERNETES, GOOGLE_VM and AZURE_VM are implemented)",
			nil,
		)
	}
	return nil
}
