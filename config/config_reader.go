package config

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/cloud-idaas/idaas-go-core-sdk/constants"
	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
	"github.com/cloud-idaas/idaas-go-core-sdk/errors"
	"github.com/cloud-idaas/idaas-go-core-sdk/util"
)

// ConfigReader 配置读取器 (§8.4)
type ConfigReader struct{}

// NewConfigReader 创建 ConfigReader
func NewConfigReader() *ConfigReader {
	return &ConfigReader{}
}

// LoadFromFile 从 JSON 文件加载配置 (§8.4)
func (r *ConfigReader) LoadFromFile(filePath string) (*IDaaSClientConfig, error) {
	data, err := util.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.NewConfigError(
				constants.LoadConfigFileFailed,
				"Config file not found: "+filePath,
				err,
			)
		}
		return nil, errors.NewConfigError(
			constants.LoadConfigFileFailed,
			"Failed to read config file "+filePath+": "+err.Error(),
			err,
		)
	}

	var config IDaaSClientConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, errors.NewConfigError(
			constants.LoadConfigFileFailed,
			"Failed to parse config file "+filePath+" (invalid JSON): "+err.Error(),
			err,
		)
	}

	// 设置 HumanAuthenticateClientId 默认值，与 Java SDK 保持一致
	if config.AuthnConfiguration != nil && config.AuthnConfiguration.HumanAuthenticateClientId == "" {
		config.AuthnConfiguration.HumanAuthenticateClientId = constants.DefaultHumanAuthenticateClientId
	} else if config.AuthnConfiguration == nil {
		config.AuthnConfiguration = &IdentityAuthenticationConfiguration{
			HumanAuthenticateClientId: constants.DefaultHumanAuthenticateClientId,
		}
	}

	return &config, nil
}

// LoadFromEnv 从环境变量加载配置 (§8.4)
//
// 当 CLIENT_ID 或 TOKEN_ENDPOINT 任一缺失时返回结构化错误，
// 避免返回"看似配置好但实际全空"的对象误导调用方。
func (r *ConfigReader) LoadFromEnv() (*IDaaSClientConfig, error) {
	clientId := strings.TrimSpace(os.Getenv(constants.EnvVarClientId))
	tokenEndpoint := strings.TrimSpace(os.Getenv(constants.EnvVarTokenEndpoint))
	if clientId == "" || tokenEndpoint == "" {
		return nil, errors.NewConfigError(
			constants.ClientIdNotFound,
			"env vars "+constants.EnvVarClientId+" and "+constants.EnvVarTokenEndpoint+" are required when loading config from environment",
			nil,
		)
	}

	config := &IDaaSClientConfig{
		ClientId:       clientId,
		InstanceId:     os.Getenv(constants.EnvVarInstanceId),
		IssuerEndpoint: os.Getenv(constants.EnvVarIssuerEndpoint),
		TokenEndpoint:  tokenEndpoint,
		Scope:          os.Getenv(constants.EnvVarScope),
	}

	// 解析 AuthnConfiguration
	if authnMethodStr := os.Getenv(constants.EnvVarAuthnMethod); authnMethodStr != "" {
		config.AuthnConfiguration = &IdentityAuthenticationConfiguration{
			AuthnMethod:               enums.TokenAuthnMethod(strings.ToLower(authnMethodStr)),
			IdentityType:              enums.AuthenticationIdentityClient,           // 默认为 CLIENT
			HumanAuthenticateClientId: constants.DefaultHumanAuthenticateClientId, // 默认值，与 Java SDK 保持一致
		}

		// 根据 authn_method 加载对应的凭证信息
		switch config.AuthnConfiguration.AuthnMethod {
		case enums.TokenAuthnMethodClientSecretBasic, enums.TokenAuthnMethodClientSecretPost:
			config.AuthnConfiguration.ClientSecretEnvVarName = constants.EnvVarClientSecret
		case enums.TokenAuthnMethodPrivateKeyJwt:
			config.AuthnConfiguration.PrivateKeyEnvVarName = constants.EnvVarPrivateKey
		}
	} else {
		// 未设置 authn_method 时，仅占位 HumanAuthenticateClientId 默认值，避免下游 nil deref
		config.AuthnConfiguration = &IdentityAuthenticationConfiguration{
			HumanAuthenticateClientId: constants.DefaultHumanAuthenticateClientId,
		}
	}

	return config, nil
}

// LoadWithPriority 按优先级加载配置 (§8.4)
//
// 优先级（与 Java SDK 保持一致）:
//  1. 显式文件路径（如果传了就硬失败，不静默回退；避免用户传错路径却看不出来）
//  2. 环境变量 CLOUD_IDAAS_CONFIG_PATH 指向的文件
//  3. 默认配置文件 ~/.cloud_idaas/client-config.json
//  4. 独立的环境变量（CLOUD_IDAAS_CLIENT_ID / CLOUD_IDAAS_TOKEN_ENDPOINT 等）
//
// 若以上来源全部失败，则返回 "Config file not found" 错误。
func (r *ConfigReader) LoadWithPriority(explicitFilePath string) (*IDaaSClientConfig, error) {
	// 1. 显式文件路径：硬失败（用户既然显式传了，传错就直接报错，不要静默回退）
	if explicitFilePath != "" {
		return r.LoadFromFile(explicitFilePath)
	}

	// 2. 环境变量 CLOUD_IDAAS_CONFIG_PATH 指向的文件
	//    用户显式设置了环境变量等同于显式传路径 → 解析失败必须硬报错，
	//    不要静默回退到下一优先级，避免"配错文件却以为用上了环境变量"。
	if envConfigPath := os.Getenv(constants.EnvConfigPathKey); envConfigPath != "" {
		return r.LoadFromFile(envConfigPath)
	}

	// 3. 默认配置文件 ~/.cloud_idaas/client-config.json
	//    文件存在但解析失败也必须硬报错，否则用户改错 JSON 永远只会看到
	//    "Config file not found"，无从排查。
	defaultPath := constants.DefaultConfigPath
	if _, statErr := os.Stat(defaultPath); statErr == nil {
		return r.LoadFromFile(defaultPath)
	}

	// 4. 独立环境变量兜底
	envConfig, envErr := r.LoadFromEnv()
	if envErr == nil {
		return envConfig, nil
	}

	// 全部来源都不足以构成可用配置
	return nil, errors.NewConfigError(
		constants.LoadConfigFileFailed,
		"Config file not found: "+defaultPath+"; and env vars CLOUD_IDAAS_CLIENT_ID / CLOUD_IDAAS_TOKEN_ENDPOINT are not fully set",
		envErr,
	)
}
