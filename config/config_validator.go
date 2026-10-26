package config

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/cloud-idaas/idaas-go-core-sdk/constants"
	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
	"github.com/cloud-idaas/idaas-go-core-sdk/errors"
	"github.com/cloud-idaas/idaas-go-core-sdk/util"
)

type ConfigValidator struct{}

func NewConfigValidator() *ConfigValidator {
	return &ConfigValidator{}
}

func (v *ConfigValidator) Validate(config *IDaaSClientConfig) error {
	// Validate 是导出方法，可能被宿主直接调用；nil 输入必须返回错误而不是 panic。
	if config == nil {
		return errors.NewConfigError(constants.ClientConfigurationNotFound, "client configuration is nil", nil)
	}

	// Normalize 阶段:对身份字段与 scope 应用 strings.TrimSpace 写回。
	// TrimSpace 仅去首尾,内部空格保留(scope 多值分隔符空格不受影响)。
	// 写回确保后续 ValidateNotBlank / validateHttpsUrl / 运行时拿到的是已清理值,
	// 而非"通过校验但带尾随空格"的值(后者会致 IdP 401 且无从定位)。
	// 重复调用幂等(trim 已 trim 值为 no-op),故多次 Validate 安全。
	normalizeTrimmedFields(config)

	if err := util.ValidateNotBlank(config.ClientId, "client_id"); err != nil {
		return errors.NewConfigError(constants.ClientIdNotFound, "Client ID is required", err)
	}

	if err := util.ValidateNotBlank(config.InstanceId, "instance_id"); err != nil {
		return errors.NewConfigError(constants.IDaaSInstanceIdNotFound, "Instance ID is required", err)
	}

	if err := util.ValidateNotBlank(config.IssuerEndpoint, "issuer_endpoint"); err != nil {
		return errors.NewConfigError(constants.IssuerEndpointNotFound, "Issuer endpoint is required", err)
	}
	// 注意：此处直接返回 validateHttpsUrl 的错误，不再二次包一层 *NotFound。
	// endpoint "存在但非法" 与 "缺失" 是两类问题，错误码必须能区分，
	// 否则调用方拿到 IssuerEndpointNotFound 却发现配置里明明写了，无从下手。
	if err := validateHttpsUrl("issuer", config.IssuerEndpoint, config.AllowInsecureEndpoint); err != nil {
		return err
	}

	if err := util.ValidateNotBlank(config.TokenEndpoint, "token_endpoint"); err != nil {
		return errors.NewConfigError(constants.TokenEndpointNotFound, "Token endpoint is required", err)
	}
	if err := validateHttpsUrl("tokenEndpoint", config.TokenEndpoint, config.AllowInsecureEndpoint); err != nil {
		return err
	}

	// 可选 endpoint：只有配置了才校验，但一旦配置就同样强制 https。
	for _, opt := range []struct{ field, value string }{
		{"deviceAuthorizationEndpoint", config.DeviceAuthorizationEndpoint},
		{"developerApiEndpoint", config.DeveloperApiEndpoint},
		{"openApiEndpoint", config.OpenApiEndpoint},
	} {
		if strings.TrimSpace(opt.value) == "" {
			continue
		}
		if err := validateHttpsUrl(opt.field, opt.value, config.AllowInsecureEndpoint); err != nil {
			return err
		}
	}

	// 验证 scope 格式 (ValidateScope 接入校验链)
	// scope 为空时表示使用默认 scope，是合法值，跳过校验。
	// 仅在调用方显式提供了 scope 时校验其格式合法性。
	if config.Scope != "" {
		if err := util.ValidateScope(config.Scope); err != nil {
			return err
		}
	}

	// 验证 AuthnConfiguration
	if config.AuthnConfiguration == nil {
		return errors.NewConfigError(constants.AuthnConfigurationNotFound, "Authn configuration is required", nil)
	}

	// identityType 必须先于 authnMethod 校验：两种身份对 authnMethod 的要求不同。
	identityType := config.AuthnConfiguration.IdentityType
	if err := validateIdentityType(identityType); err != nil {
		return err
	}

	if identityType == enums.AuthenticationIdentityHuman {
		// HUMAN 走 RFC 8628 device code 流程，deviceAuthorizationEndpoint 是唯一入口，
		// 必须在 init 阶段拦截，而不是等到首次取凭证（预热失败只打 WARN）才暴露。
		// humanAuthenticateClientId 留空时回落 DefaultHumanAuthenticateClientId，此处不强制。
		if strings.TrimSpace(config.DeviceAuthorizationEndpoint) == "" {
			return errors.NewConfigError(constants.DeviceAuthorizationEndpointNotFound, "deviceAuthorizationEndpoint is required for HUMAN identityType", nil)
		}
		// device code 是公共客户端流程，不做客户端认证，authnMethod 不需要设置（与 Java/Python 对齐）。
		// 若显式设置了，仍按对应方式校验字段，避免错误配置被静默吞掉。
		if config.AuthnConfiguration.AuthnMethod == "" {
			// 跳过 authnMethod 校验,但仍需执行 staleValueBehavior 和 HTTP 配置等
			// 通用校验,否则非法值(如 "INVALID")会绕过校验进入运行时,
			// 在 supplier 无 default 分支时返回过期 token 当成功。
			if err := validateStaleValueBehavior(config.StaleValueBehavior); err != nil {
				return err
			}
			return validateHttpConfiguration(config.HttpConfiguration)
		}
	}

	if err := validateAuthnMethod(config); err != nil {
		return err
	}

	// 验证 staleValueBehavior 取值(非空时必须在白名单内)。
	// 空值合法:factory 层会规范化为 REFRESH,与 beta 阶段默认行为一致。
	if err := validateStaleValueBehavior(config.StaleValueBehavior); err != nil {
		return err
	}

	// 验证 HTTP 配置: connectTimeout / readTimeout ∈ [2000, 60000]
	// 0 表示"未配置，使用默认值"，不拦截；只在显式配置了值时校验范围。
	return validateHttpConfiguration(config.HttpConfiguration)
}

// validateAuthnMethod 根据 authnMethod 校验对应的凭证字段（覆盖全部已支持的认证方式，确保配置错误能尽早暴露）。
func validateAuthnMethod(config *IDaaSClientConfig) error {
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
	case enums.TokenAuthnMethodPca:
		// PCA (Private CA) 校验与 Java SDK ValidatorUtil 对齐：4 个字段全部必填
		if config.AuthnConfiguration.PrivateKeyEnvVarName == "" {
			return errors.NewConfigError(constants.PrivateKeyEnvVarNameNotFound, "Private key env var name is required for PCA authentication", nil)
		}
		if config.AuthnConfiguration.ApplicationFederatedCredentialName == "" {
			return errors.NewConfigError(constants.ApplicationFederatedCredentialNameNotFound, "applicationFederatedCredentialName is required for PCA authentication", nil)
		}
		if config.AuthnConfiguration.ClientX509Certificate == "" {
			return errors.NewConfigError(constants.ClientX509CertificateNotFound, "clientX509Certificate (leaf certificate PEM) is required for PCA authentication", nil)
		}
		if config.AuthnConfiguration.X509CertChains == "" {
			return errors.NewConfigError(constants.X509CertChainsNotFound, "x509CertChains (intermediate certificate chain PEM) is required for PCA authentication", nil)
		}
	case enums.TokenAuthnMethodPkcs7:
		if config.AuthnConfiguration.ApplicationFederatedCredentialName == "" {
			return errors.NewConfigError(constants.ApplicationFederatedCredentialNameNotFound, "applicationFederatedCredentialName is required for PKCS7 federated authentication", nil)
		}
		if err := validatePkcs7DeployEnvironment(config.AuthnConfiguration.ClientDeployEnvironment); err != nil {
			return err
		}
	case enums.TokenAuthnMethodOidc:
		if config.AuthnConfiguration.ApplicationFederatedCredentialName == "" {
			return errors.NewConfigError(constants.ApplicationFederatedCredentialNameNotFound, "applicationFederatedCredentialName is required for OIDC federated authentication", nil)
		}
		if err := validateOidcDeployEnvironment(config); err != nil {
			return err
		}
	case enums.TokenAuthnMethodPlugin:
		if config.AuthnConfiguration.PluginName == "" {
			return errors.NewConfigError(constants.PluginNameNotFound, "pluginName is required when authnMethod is plugin", nil)
		}
		// PLUGIN 方式需要 openApiEndpoint（与 Java SDK 对齐，插件凭证获取依赖 OpenAPI 端点）
		// 空白字符串 " " 通过 == "" 检查,normalizeEndpoints trim 后变为空,
		// 插件拿到空端点仍继续执行。用 TrimSpace 拦截纯空白值。
		if strings.TrimSpace(config.OpenApiEndpoint) == "" {
			return errors.NewConfigError(constants.OpenApiEndpointNotFound, "openApiEndpoint is required for PLUGIN authentication", nil)
		}
	case "":
		// CLIENT 身份 authnMethod 缺失 = authnConfiguration 不完整（HUMAN 已在调用方提前放行），
		// 复用 AuthnConfigurationNotFound，不单独引入 AuthnMethodNotFound：调用方的处置动作与前者
		// 完全一致（补全 authnConfiguration），多一个错误码只会增加 SDK 间对齐成本。
		return errors.NewConfigError(constants.AuthnConfigurationNotFound, "authnMethod is required in authnConfiguration for CLIENT identityType", nil)
	default:
		// 含 authnMethod=none 等非规范值：IDaaS 凭证 SDK 的全部调用场景都需要机密客户端身份，
		// "public client / 无客户端认证"会让任何能访问 token endpoint 的进程冒用 clientId，
		// 因此直接拒绝启动而非静默放行。TokenAuthnMethodNone 常量已删除，
		// 此 default 分支同时拦截旧的 "none" 字面量和任何未来新增的非法值。
		return errors.NewConfigError(constants.UnsupportedAuthenticationMethod, "Unsupported authnMethod: "+string(config.AuthnConfiguration.AuthnMethod), nil)
	}
	return nil
}

// validateHttpConfiguration 校验 HTTP 超时范围（补齐 constants 中已定义但零引用的
// ConnectTimeoutNotValid / ReadTimeoutNotValid）。nil 或字段为 0 放行（0=未配置），
// 否则 connectTimeout / readTimeout ∈ [2000, 60000] ms。
// 下界 2s 防 DNS 抖动误超时，上界 60s 防 token 端点局部故障放大成整进程阻塞。
func validateHttpConfiguration(httpConfig *HttpConfiguration) error {
	if httpConfig == nil {
		return nil
	}
	if httpConfig.ConnectTimeout != 0 {
		if httpConfig.ConnectTimeout < 2000 || httpConfig.ConnectTimeout > 60000 {
			return errors.NewConfigError(
				constants.ConnectTimeoutNotValid,
				"connectTimeout must be in [2000, 60000] ms, got: "+
					strconv.Itoa(httpConfig.ConnectTimeout),
				nil,
			)
		}
	}
	if httpConfig.ReadTimeout != 0 {
		if httpConfig.ReadTimeout < 2000 || httpConfig.ReadTimeout > 60000 {
			return errors.NewConfigError(
				constants.ReadTimeoutNotValid,
				"readTimeout must be in [2000, 60000] ms, got: "+
					strconv.Itoa(httpConfig.ReadTimeout),
				nil,
			)
		}
	}
	return nil
}

// validateStaleValueBehavior 校验 staleValueBehavior 取值合法性。
// 空值放行(由 factory 规范化为 REFRESH);非空值必须在 BLOCK/ALLOW/REFRESH 白名单内。
func validateStaleValueBehavior(behavior enums.StaleValueBehavior) error {
	switch behavior {
	case "", enums.StaleValueBehaviorBlock, enums.StaleValueBehaviorAllow, enums.StaleValueBehaviorRefresh:
		return nil
	default:
		return errors.NewConfigError(
			constants.InvalidStaleValueBehavior,
			"Unsupported staleValueBehavior: "+string(behavior)+" (supported: BLOCK, ALLOW, REFRESH)",
			nil,
		)
	}
}

// validateIdentityType 校验 identityType 取值 (UnsupportedIdentityType)。
// 留空视为 CLIENT（由 Defaulting 阶段补齐），此处只拦截明确的非法值。
func validateIdentityType(identityType enums.AuthenticationIdentityEnum) error {
	switch identityType {
	case "", enums.AuthenticationIdentityClient, enums.AuthenticationIdentityHuman:
		return nil
	default:
		return errors.NewConfigError(
			constants.UnsupportedIdentityType,
			"Unsupported identityType: "+string(identityType)+" (supported: CLIENT, HUMAN)",
			nil,
		)
	}
}

// normalizeTrimmedFields 对配置的身份字段与 scope 应用 strings.TrimSpace 写回。
//
// 覆盖:ClientId/InstanceId/各 endpoint/oidcTokenFilePath(及其 env var 名)/scope。
// TrimSpace 仅去首尾空白,内部空格保留——故 scope 的多值分隔符空格不受影响
// (如 " openid profile " → "openid profile")。URL/ID 字段首尾空格无语义,trim 安全。
// 写回是 input config 字段 mutation;调用方若需保留原始值须在 Load 前深拷贝
// (默认 Initialize 后冻结,见 config 包级 doc)。
func normalizeTrimmedFields(c *IDaaSClientConfig) {
	c.ClientId = strings.TrimSpace(c.ClientId)
	c.InstanceId = strings.TrimSpace(c.InstanceId)
	c.IssuerEndpoint = strings.TrimSpace(c.IssuerEndpoint)
	c.TokenEndpoint = strings.TrimSpace(c.TokenEndpoint)
	c.DeviceAuthorizationEndpoint = strings.TrimSpace(c.DeviceAuthorizationEndpoint)
	c.DeveloperApiEndpoint = strings.TrimSpace(c.DeveloperApiEndpoint)
	c.OpenApiEndpoint = strings.TrimSpace(c.OpenApiEndpoint)
	c.Scope = strings.TrimSpace(c.Scope)
	if c.AuthnConfiguration != nil {
		c.AuthnConfiguration.OidcTokenFilePath = strings.TrimSpace(c.AuthnConfiguration.OidcTokenFilePath)
		c.AuthnConfiguration.OidcTokenFilePathEnvVarName = strings.TrimSpace(c.AuthnConfiguration.OidcTokenFilePathEnvVarName)
	}
}

// validateHttpsUrl 校验字符串是否为合法的 **https** 绝对 URL（必须含 scheme 与 host）。
// 强制 https：endpoint 承载 OAuth2 凭证交换，明文 http 会让 client_secret/access_token
// 在链路裸奔。正常链路由 util.NormalizeEndpoint 在 factory 阶段把裸 host 补全为 https://、
// http:// 提升为 https://（与 Java/Python 对齐）；本函数对未经归一化的裸 host 也拒绝，作为
// 纵深防御。allowInsecure=true 时接受 http:// 仅限本地联调（factory 每次 init 打 WARN），
// 非 http/https 的 scheme 一律拒绝。
func validateHttpsUrl(field, raw string, allowInsecure bool) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return errors.NewConfigError(constants.InvalidEndpointFormat, field+" is not a parsable URL", err)
	}
	if u.Scheme != "https" {
		if allowInsecure && u.Scheme == "http" {
			// 逃生门开启：允许 http://，但仍校验 host
		} else {
			return errors.NewConfigError(
				constants.InvalidEndpointScheme,
				field+" must use https scheme (got scheme: \""+u.Scheme+"\"); plaintext http is rejected because endpoints carry OAuth2 credentials",
				nil,
			)
		}
	}
	if u.Host == "" {
		return errors.NewConfigError(constants.InvalidEndpointFormat, field+" must contain a host", nil)
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
	enums.ClientDeployEnvironmentComputer:   {},
}

// validatePkcs7DeployEnvironment 校验 PKCS7 认证的部署环境
//
// 校验规则：
// - clientDeployEnvironment 必须显式提供（与 Java SDK 保持一致：PKCS7 必须明确指定运行环境）
// - 取值必须在已实现的白名单内（当前为 ALIBABA_CLOUD_ECS / AWS_EC2）
func validatePkcs7DeployEnvironment(deployEnv enums.ClientDeployEnvironmentEnum) error {
	if deployEnv == "" {
		return errors.NewConfigError(
			constants.ClientDeployEnvironmentNotFound,
			"clientDeployEnvironment is required for PKCS7 authentication (supported: ALIBABA_CLOUD_ECS, AWS_EC2)",
			nil,
		)
	}
	if _, ok := supportedPkcs7DeployEnvironments[deployEnv]; !ok {
		return errors.NewConfigError(
			constants.UnsupportedClientDeployEnvironment,
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
//   - 取值必须在已实现的白名单内（KUBERNETES / GOOGLE_VM / AZURE_VM / COMPUTER）
//   - GOOGLE_VM：依赖 issuer endpoint 作为元数据服务请求的 audience（基础字段已在 Validate 入口处校验）
//   - COMPUTER：依赖 oidcTokenFilePath 或 oidcTokenFilePathEnvVarName（本地开发模式，无默认路径回落）；
//     配置阶段只检查字段非空,环境变量的实际取值在运行时校验(fetchOidcToken)。
func validateOidcDeployEnvironment(config *IDaaSClientConfig) error {
	deployEnv := config.AuthnConfiguration.ClientDeployEnvironment
	if deployEnv == "" {
		return errors.NewConfigError(
			constants.ClientDeployEnvironmentNotFound,
			"clientDeployEnvironment is required for OIDC authentication (supported: KUBERNETES, GOOGLE_VM, AZURE_VM, COMPUTER)",
			nil,
		)
	}
	if _, ok := supportedOidcDeployEnvironments[deployEnv]; !ok {
		return errors.NewConfigError(
			constants.UnsupportedClientDeployEnvironment,
			"Unsupported clientDeployEnvironment for OIDC authentication: "+string(deployEnv)+
				" (currently only KUBERNETES, GOOGLE_VM, AZURE_VM and COMPUTER are implemented)",
			nil,
		)
	}
	// COMPUTER(本地开发模式)无默认 token 路径回落,必须在配置阶段就检查
	// oidcTokenFilePath / oidcTokenFilePathEnvVarName 至少一个非空,
	// 否则错误只会在运行时 fetchOidcToken 暴露,延迟排查。
	// KUBERNETES 有 K8sServiceAccountTokenPath 默认回落,不在此检查。
	// GOOGLE_VM / AZURE_VM 使用元数据服务,不需要 token 文件。
	if deployEnv == enums.ClientDeployEnvironmentComputer {
		// 用 TrimSpace 拦截纯空白值:空白字符串通过 == "" 检查,但
		// fetchOidcToken 后续会用空白路径读文件。
		if strings.TrimSpace(config.AuthnConfiguration.OidcTokenFilePath) == "" &&
			strings.TrimSpace(config.AuthnConfiguration.OidcTokenFilePathEnvVarName) == "" {
			return errors.NewConfigError(
				constants.OidcTokenFilePathNotFound,
				"oidcTokenFilePath or oidcTokenFilePathEnvVarName is required for OIDC authentication with COMPUTER deploy environment",
				nil,
			)
		}
	}
	return nil
}
