package implementation

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"net/url"
	"os"

	"github.com/cloud-idaas/idaas-go-core-sdk/config"
	"github.com/cloud-idaas/idaas-go-core-sdk/constants"
	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
	"github.com/cloud-idaas/idaas-go-core-sdk/errors"
	"github.com/cloud-idaas/idaas-go-core-sdk/http"
	"github.com/cloud-idaas/idaas-go-core-sdk/internal/implementation/authentication"
	"github.com/cloud-idaas/idaas-go-core-sdk/oauth2"
	"github.com/cloud-idaas/idaas-go-core-sdk/provider"
	"github.com/cloud-idaas/idaas-go-core-sdk/util"
)

// 本文件是 machine provider 与 token-exchange provider 共用的客户端认证材料获取逻辑：
// 私钥、client secret、PKCS7 attested document、OIDC token。
// 每次调用都重新读取环境变量 / 元数据服务，凭证轮换后无需重建 provider。

// readClientSecret 从 ClientSecretEnvVarName 指向的环境变量读取 client secret。
func readClientSecret(cfg *config.IDaaSClientConfig) (string, error) {
	envName := cfg.AuthnConfiguration.ClientSecretEnvVarName
	clientSecret := os.Getenv(envName)
	if clientSecret == "" {
		return "", errors.NewConfigError(constants.ClientSecretNotFound, "Client secret not found in environment variable: "+envName, nil)
	}
	return clientSecret, nil
}

// loadClientPrivateKey 从环境变量加载 PEM 私钥，供 PCA / private_key_jwt 共用。
func loadClientPrivateKey(cfg *config.IDaaSClientConfig, authnMethodLabel string) (interface{}, error) {
	authnConf := cfg.AuthnConfiguration
	if authnConf.PrivateKeyEnvVarName == "" {
		return nil, errors.NewConfigError(
			constants.PrivateKeyEnvVarNameNotFound,
			"privateKeyEnvVarName is required for "+authnMethodLabel,
			nil,
		)
	}
	privateKeyDataStr := os.Getenv(authnConf.PrivateKeyEnvVarName)
	if privateKeyDataStr == "" {
		return nil, errors.NewConfigError(
			constants.PrivateKeyNotFound,
			"Private key not found in environment variable: "+authnConf.PrivateKeyEnvVarName,
			nil,
		)
	}
	pemBytes, err := util.LoadPrivateKeyMaterial(privateKeyDataStr)
	if err != nil {
		return nil, errors.NewConfigError(
			constants.PrivateKeyInvalid,
			"Invalid private key from env var "+authnConf.PrivateKeyEnvVarName+": "+err.Error(),
			err,
		)
	}
	privateKey, err := util.ParsePrivateKeyFromPEM(pemBytes)
	if err != nil {
		return nil, errors.NewConfigError(
			constants.PrivateKeyInvalid,
			"Failed to parse private key from env var "+authnConf.PrivateKeyEnvVarName+": "+err.Error(),
			err,
		)
	}
	return privateKey, nil
}

// signClientAssertion 用私钥签发客户端 JWT 断言：iss = sub = clientId, aud = tokenEndpoint，
// 与 authentication.StaticPrivateKeyAssertionProvider / StaticX509AssertionProvider 一致。
func signClientAssertion(clientId, tokenEndpoint string, privateKey interface{}) (string, error) {
	claims := util.BuildJwtClaims(clientId, clientId, tokenEndpoint, util.DefaultClientAssertionTTL)
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		return util.SignJwtRS256(claims, key)
	case *ecdsa.PrivateKey:
		return util.SignJwtES256(claims, key)
	default:
		return "", errors.NewConfigError(
			constants.UnsupportedPrivateKeyType,
			fmt.Sprintf("unsupported private key type %T (only RSA or ECDSA is supported)", privateKey),
			nil,
		)
	}
}

// fetchPkcs7AttestedDocument 根据 deployEnv 路由到具体的 PKCS7 attestation provider，返回 attested document。
// ctx 透传到 attestation provider 的元数据服务调用。
func fetchPkcs7AttestedDocument(ctx context.Context, cfg *config.IDaaSClientConfig, httpClient http.HttpClient, deployEnv enums.ClientDeployEnvironmentEnum) (string, error) {
	if cfg.AuthnConfiguration.ApplicationFederatedCredentialName == "" {
		return "", errors.NewConfigError(
			constants.ApplicationFederatedCredentialNameNotFound,
			"applicationFederatedCredentialName is required for PKCS7 authentication",
			nil,
		)
	}

	switch deployEnv {
	case enums.ClientDeployEnvironmentAlibabaCloudEcs:
		return authentication.NewAlibabaCloudEcsAttestedDocumentProvider(
			httpClient,
			cfg.InstanceId,
			0, // 使用默认 TTL 3600s
		).GetAttestedDocumentWithContext(ctx)
	case enums.ClientDeployEnvironmentAwsEc2:
		return authentication.NewAwsEc2AttestedDocumentProvider(httpClient, 0).GetAttestedDocumentWithContext(ctx)
	default:
		return "", errors.NewConfigError(
			constants.UnsupportedClientDeployEnvironment,
			"Unsupported clientDeployEnvironment for PKCS7 authentication: "+string(deployEnv)+
				" (currently only ALIBABA_CLOUD_ECS and AWS_EC2 are implemented)",
			nil,
		)
	}
}

// fetchOidcToken 根据 deployEnv 路由到具体的 OIDC token provider，返回 OIDC token。
// ctx 透传到 OIDC token provider 的元数据服务调用。
func fetchOidcToken(ctx context.Context, cfg *config.IDaaSClientConfig, httpClient http.HttpClient, deployEnv enums.ClientDeployEnvironmentEnum) (string, error) {
	authnConf := cfg.AuthnConfiguration
	// applicationFederatedCredentialName 非空校验已在 config.ConfigValidator.Validate 中完成，此处不再重复。

	var oidcTokenProvider provider.OidcTokenProvider
	switch deployEnv {
	case enums.ClientDeployEnvironmentKubernetes:
		tokenPath := authnConf.OidcTokenFilePath
		if tokenPath == "" && authnConf.OidcTokenFilePathEnvVarName != "" {
			tokenPath = os.Getenv(authnConf.OidcTokenFilePathEnvVarName)
			// OidcTokenFilePathEnvVarName was explicitly configured but the env var
			// resolves to empty — the user intended a custom token path, not the
			// default SA token. Returning an error avoids silently authenticating
			// under the default service-account identity. Only fall back to the
			// default K8s SA token path when NEITHER OidcTokenFilePath nor
			// OidcTokenFilePathEnvVarName is configured (handled below).
			if tokenPath == "" {
				return "", errors.NewConfigError(
					constants.OidcTokenFilePathNotFound,
					"oidcTokenFilePathEnvVarName is configured but environment variable "+authnConf.OidcTokenFilePathEnvVarName+" is not set or empty",
					nil,
				)
			}
		}
		if tokenPath == "" {
			tokenPath = constants.K8sServiceAccountTokenPath
		}
		oidcTokenProvider = authentication.NewFileOidcTokenProvider(tokenPath)
	case enums.ClientDeployEnvironmentGoogleVm:
		// GCP VM OIDC：从元数据服务获取 ID Token
		// audience 取 issuer 的 origin（scheme://host[:port]），与 IDaaS 联邦凭证侧约定一致
		if cfg.IssuerEndpoint == "" {
			return "", errors.NewConfigError(
				constants.IssuerEndpointNotFound,
				"issuer endpoint is required as audience source for GCP VM OIDC authentication",
				nil,
			)
		}
		audience, err := util.ExtractUrlOrigin(cfg.IssuerEndpoint)
		if err != nil {
			return "", errors.NewConfigError(
				constants.InvalidEndpointFormat,
				"failed to extract origin from issuer endpoint for GCP VM OIDC audience: "+err.Error(),
				err,
			)
		}
		oidcTokenProvider = authentication.NewGcpVmOidcTokenProvider(httpClient, audience)
	case enums.ClientDeployEnvironmentAzureVm:
		// Azure VM OIDC：从 IMDS Managed Identity 获取 ID Token
		// resource 固定为 https://management.azure.com/
		// ID010: 注入调用方 ctx 作为 baseCtx,使后台 IMDS fetch worker 的
		// refreshCtx(WithTimeout(baseCtx,...)) 能感知调用方取消;否则 baseCtx=nil
		// 回退 Background,调用方取消后 worker 仍跑到 imdsTimeout 才停(泄漏窗口)。
		// provider 是 fetchOidcToken 局部变量(每次 GetCredential 新建),注入 per-call ctx 安全。
		oidcTokenProvider = authentication.NewAzureVmOidcTokenProvider(httpClient).WithBaseContext(ctx)
	case enums.ClientDeployEnvironmentComputer:
		// COMPUTER（本地开发模式）：从配置的文件路径读取 OIDC token
		// 与 KUBERNETES 的区别：不回落到默认 K8s service account 路径，
		// 必须显式提供 oidcTokenFilePath 或 oidcTokenFilePathEnvVarName。
		tokenPath := authnConf.OidcTokenFilePath
		if tokenPath == "" && authnConf.OidcTokenFilePathEnvVarName != "" {
			tokenPath = os.Getenv(authnConf.OidcTokenFilePathEnvVarName)
		}
		if tokenPath == "" {
			return "", errors.NewConfigError(
				constants.OidcTokenFilePathNotFound,
				"oidcTokenFilePath or oidcTokenFilePathEnvVarName is required for OIDC authentication with COMPUTER deploy environment",
				nil,
			)
		}
		oidcTokenProvider = authentication.NewFileOidcTokenProvider(tokenPath)
	default:
		return "", errors.NewConfigError(
			constants.UnsupportedClientDeployEnvironment,
			"Unsupported clientDeployEnvironment for OIDC authentication: "+string(deployEnv)+
				" (currently only KUBERNETES, GOOGLE_VM, AZURE_VM and COMPUTER are implemented)",
			nil,
		)
	}

	return oidcTokenProvider.GetOidcTokenWithContext(ctx)
}

// buildClientAuthentication 按 AuthnMethod 构造 token endpoint 请求的客户端认证部分，
// 与 Java SDK token exchange 的客户端认证一致。client_id 总是放在 form 里。
// PLUGIN 由插件自行获取凭证，无法用于 token exchange，返回 UnsupportedAuthenticationMethod。
// ctx 透传到 PKCS7/OIDC 元数据服务调用,使调用方可取消长时间挂起的元数据调用。
func buildClientAuthentication(ctx context.Context, cfg *config.IDaaSClientConfig, httpClient http.HttpClient) (oauth2.ClientAuthentication, error) {
	authnConf := cfg.AuthnConfiguration
	if authnConf == nil {
		return oauth2.ClientAuthentication{}, errors.NewConfigError(constants.AuthnConfigurationNotFound, "Authn configuration is required", nil)
	}

	form := url.Values{}
	form.Set(constants.ParamClientID, cfg.ClientId)
	auth := oauth2.ClientAuthentication{Form: form}

	setAssertion := func(assertionType, assertion string) {
		form.Set(constants.ParamClientAssertionType, assertionType)
		form.Set(constants.ParamClientAssertion, assertion)
	}

	switch authnConf.AuthnMethod {
	case enums.TokenAuthnMethodClientSecretBasic:
		secret, err := readClientSecret(cfg)
		if err != nil {
			return oauth2.ClientAuthentication{}, err
		}
		// (RFC 6749): client_id 与 client_secret 在拼接前需各自做
		// application/x-www-form-urlencoded 编码,再 base64。对纯字母数字的 id/secret
		// 是 no-op,但对含 ':' / '+' / 空格等特殊字符的凭证能避免 basic 头被截断/误解析。
		basic := base64.StdEncoding.EncodeToString(
			[]byte(url.QueryEscape(cfg.ClientId) + ":" + url.QueryEscape(secret)))
		auth.Headers = map[string]string{"Authorization": "Basic " + basic}
	case enums.TokenAuthnMethodClientSecretPost:
		secret, err := readClientSecret(cfg)
		if err != nil {
			return oauth2.ClientAuthentication{}, err
		}
		form.Set(constants.ParamClientSecret, secret)
	case enums.TokenAuthnMethodClientSecretJwt:
		secret, err := readClientSecret(cfg)
		if err != nil {
			return oauth2.ClientAuthentication{}, err
		}
		claims := util.BuildJwtClaims(cfg.ClientId, cfg.ClientId, cfg.TokenEndpoint, util.DefaultClientAssertionTTL)
		assertion, err := util.SignJwtHS256(claims, []byte(secret))
		if err != nil {
			return oauth2.ClientAuthentication{}, err
		}
		setAssertion(constants.AssertionTypeJwtBearer, assertion)
	case enums.TokenAuthnMethodPrivateKeyJwt:
		key, err := loadClientPrivateKey(cfg, "private_key_jwt")
		if err != nil {
			return oauth2.ClientAuthentication{}, err
		}
		assertion, err := signClientAssertion(cfg.ClientId, cfg.TokenEndpoint, key)
		if err != nil {
			return oauth2.ClientAuthentication{}, err
		}
		setAssertion(constants.AssertionTypeJwtBearer, assertion)
	case enums.TokenAuthnMethodPca:
		if authnConf.ClientX509Certificate == "" {
			return oauth2.ClientAuthentication{}, errors.NewConfigError(constants.ClientX509CertificateNotFound, "clientX509Certificate is required for pca", nil)
		}
		key, err := loadClientPrivateKey(cfg, "pca")
		if err != nil {
			return oauth2.ClientAuthentication{}, err
		}
		assertion, err := signClientAssertion(cfg.ClientId, cfg.TokenEndpoint, key)
		if err != nil {
			return oauth2.ClientAuthentication{}, err
		}
		setAssertion(constants.AssertionTypeX509JwtBearer, assertion)
		form.Set(constants.ParamClientX509, authnConf.ClientX509Certificate)
		if authnConf.X509CertChains != "" {
			form.Set(constants.ParamClientX509Chain, authnConf.X509CertChains)
		}
		form.Set(constants.ParamApplicationFederatedCredentialName, authnConf.ApplicationFederatedCredentialName)
	case enums.TokenAuthnMethodPkcs7:
		doc, err := fetchPkcs7AttestedDocument(ctx, cfg, httpClient, authnConf.ClientDeployEnvironment)
		if err != nil {
			return oauth2.ClientAuthentication{}, err
		}
		setAssertion(constants.AssertionTypePkcs7Bearer, doc)
		form.Set(constants.ParamApplicationFederatedCredentialName, authnConf.ApplicationFederatedCredentialName)
	case enums.TokenAuthnMethodOidc:
		oidcToken, err := fetchOidcToken(ctx, cfg, httpClient, authnConf.ClientDeployEnvironment)
		if err != nil {
			return oauth2.ClientAuthentication{}, err
		}
		setAssertion(constants.AssertionTypeIdTokenBearer, oidcToken)
		form.Set(constants.ParamApplicationFederatedCredentialName, authnConf.ApplicationFederatedCredentialName)
	default:
		return oauth2.ClientAuthentication{}, errors.NewClientError(
			constants.UnsupportedAuthenticationMethod,
			"Unsupported authn method for token exchange: "+string(authnConf.AuthnMethod),
			nil,
		)
	}
	return auth, nil
}
