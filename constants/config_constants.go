package constants

import (
	"os"
	"path/filepath"
)

// 配置路径常量 (§13.8) - 与 Java SDK 保持一致
const (
	// JVMConfigPathKey Java SDK 中的 JVM 参数名（Go 中不使用）
	JVMConfigPathKey = "cloud_idaas_config_path"

	// EnvConfigPathKey 环境变量名，与 Java SDK 保持一致
	EnvConfigPathKey = "CLOUD_IDAAS_CONFIG_PATH"
)

// DefaultConfigPath 默认配置文件路径，与 Java SDK 保持一致
// ~/.cloud_idaas/client-config.json
var DefaultConfigPath = filepath.Join(os.Getenv("HOME"), ".cloud_idaas", "client-config.json")

// 环境变量名常量 (§13.8) - 与 Java SDK 保持一致
const (
	EnvVarClientId                 = "CLOUD_IDAAS_CLIENT_ID"
	EnvVarClientSecret             = "CLOUD_IDAAS_CLIENT_SECRET"
	EnvVarPrivateKey               = "CLOUD_IDAAS_PRIVATE_KEY"
	EnvVarPrivateKeyPath           = "CLOUD_IDAAS_PRIVATE_KEY_PATH"
	EnvVarInstanceId               = "CLOUD_IDAAS_INSTANCE_ID"
	EnvVarIssuerEndpoint           = "CLOUD_IDAAS_ISSUER_ENDPOINT"
	EnvVarTokenEndpoint            = "CLOUD_IDAAS_TOKEN_ENDPOINT"
	EnvVarAuthnMethod              = "CLOUD_IDAAS_AUTHN_METHOD"
	EnvVarScope                    = "CLOUD_IDAAS_SCOPE"
	EnvHumanCredentialCachePathKey = "CLOUD_IDAAS_HUMAN_CREDENTIAL_CACHE_PATH"
)
