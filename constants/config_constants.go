package constants

import (
	"os"
	"path/filepath"
)

// 配置路径常量 - 与 Java SDK 保持一致
const (
	// EnvConfigPathKey 环境变量名，与 Java SDK 保持一致
	EnvConfigPathKey = "CLOUD_IDAAS_CONFIG_PATH"
)

// Default HTTP timeouts (milliseconds).
// Single source of truth shared by config defaults and http client fallback (DRY).
// Aligned with Java / Python SDK: 5000ms connect / 10000ms read.
const (
	DefaultConnectTimeoutMs = 5000
	DefaultReadTimeoutMs    = 10000
)

// DefaultConfigPath 默认配置文件路径，与 Java SDK 保持一致
// ~/.cloud_idaas/client-config.json
//
// 使用 os.UserHomeDir() 而非 os.Getenv("HOME")，因为后者在 Windows（USERPROFILE）、
// 部分容器镜像和 systemd unit 中为空，导致路径变为 /.cloud_idaas/...。
// os.UserHomeDir() 跨平台兼容 Linux / macOS / Windows。
var DefaultConfigPath = defaultConfigPath()

func defaultConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		// 回退到当前目录，避免拼出 /.cloud_idaas/... 这样的无效路径
		return filepath.Join(".", ".cloud_idaas", "client-config.json")
	}
	return filepath.Join(home, ".cloud_idaas", "client-config.json")
}

// 环境变量名常量 - 与 Java SDK 保持一致
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
