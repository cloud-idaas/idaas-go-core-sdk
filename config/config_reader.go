package config

import (
	"context"
	"encoding/json"
	"os"
	"strings"

	"github.com/cloud-idaas/idaas-go-core-sdk/constants"
	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
	"github.com/cloud-idaas/idaas-go-core-sdk/errors"
	"github.com/cloud-idaas/idaas-go-core-sdk/logger"
	"github.com/cloud-idaas/idaas-go-core-sdk/util"
)

type ConfigReader struct{}

func NewConfigReader() *ConfigReader {
	return &ConfigReader{}
}

// LoadFromFile 从 JSON 文件加载配置
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

	// 未知配置键告警（只告警不失败）。
	// 用 json.Decoder + DisallowUnknownFields 探测，命中未知键时打 WARN + "did you mean"。
	// 不拦截：老配置文件因 SDK 新增字段而被拒绝是不可接受的。
	warnUnknownConfigKeys(data, filePath)

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

// LoadFromEnv 从环境变量加载配置
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
		InstanceId:     strings.TrimSpace(os.Getenv(constants.EnvVarInstanceId)),
		IssuerEndpoint: strings.TrimSpace(os.Getenv(constants.EnvVarIssuerEndpoint)),
		TokenEndpoint:  tokenEndpoint,
		Scope:          os.Getenv(constants.EnvVarScope),
	}

	if authnMethodStr := strings.TrimSpace(os.Getenv(constants.EnvVarAuthnMethod)); authnMethodStr != "" {
		config.AuthnConfiguration = &IdentityAuthenticationConfiguration{
			AuthnMethod:               enums.TokenAuthnMethod(strings.ToLower(authnMethodStr)),
			IdentityType:              enums.AuthenticationIdentityClient,         // 默认为 CLIENT
			HumanAuthenticateClientId: constants.DefaultHumanAuthenticateClientId, // 默认值，与 Java SDK 保持一致
		}

		switch config.AuthnConfiguration.AuthnMethod {
		case enums.TokenAuthnMethodClientSecretBasic, enums.TokenAuthnMethodClientSecretPost,
			enums.TokenAuthnMethodClientSecretJwt:
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

// LoadWithPriority 按三级优先级加载配置（与 Java SDK 对齐）：
// 1. 显式文件路径：传了就硬失败，不静默回退，避免传错路径看不出
// 2. 环境变量 CLOUD_IDAAS_CONFIG_PATH 指向的文件
// 3. 默认配置文件 ~/.cloud_idaas/client-config.json
//
// 原"独立环境变量兜底"（LoadFromEnv）已从默认链移除：它会凭零散环境变量
// 让 SDK 静默启动而用户不知配置来源，违反三级契约。现 LoadFromEnv 改为
// 显式导出，仅在调用方主动使用时生效。三级来源全部失败 = 配置缺失，硬失败。
func (r *ConfigReader) LoadWithPriority(explicitFilePath string) (*IDaaSClientConfig, error) {
	// 1. 显式文件路径：硬失败（用户既然显式传了，传错就直接报错，不要静默回退）
	if explicitFilePath != "" {
		return r.LoadFromFile(explicitFilePath)
	}

	// 2. 环境变量 CLOUD_IDAAS_CONFIG_PATH 指向的文件
	// 用户显式设置了环境变量等同于显式传路径 → 解析失败必须硬报错，
	// 不要静默回退到下一优先级，避免"配错文件却以为用上了环境变量"。
	if envConfigPath := os.Getenv(constants.EnvConfigPathKey); envConfigPath != "" {
		return r.LoadFromFile(envConfigPath)
	}

	// 3. 默认配置文件 ~/.cloud_idaas/client-config.json
	// 文件存在但解析失败也必须硬报错，否则用户改错 JSON 永远只会看到
	// "Config file not found"，无从排查。
	defaultPath := constants.DefaultConfigPath
	if _, statErr := os.Stat(defaultPath); statErr == nil {
		return r.LoadFromFile(defaultPath)
	}

	// 不再回退到 LoadFromEnv。三级来源全部失败 = 配置缺失，硬失败。
	return nil, errors.NewConfigError(
		constants.LoadConfigFileFailed,
		"Config file not found: "+defaultPath+
			"; set CLOUD_IDAAS_CONFIG_PATH env var or provide an explicit path"+
			"; or call config.LoadFromEnv() explicitly if loading from environment variables",
		nil,
	)
}

// knownTopLevelConfigKeys IDaaSClientConfig 的已知 JSON 顶层字段名集合。
var knownTopLevelConfigKeys = map[string]struct{}{
	"clientId":                    {},
	"idaasInstanceId":             {},
	"issuer":                      {},
	"tokenEndpoint":               {},
	"deviceAuthorizationEndpoint": {},
	"developerApiEndpoint":        {},
	"openApiEndpoint":             {},
	"authnConfiguration":          {},
	"httpConfiguration":           {},
	"allowInsecureEndpoint":       {},
	"scope":                       {},
	"staleValueBehavior":          {},
	"failureMode":                 {},
	"metricsEnabled":              {},
	"logLevel":                    {},
}

// knownAuthnConfigKeys IdentityAuthenticationConfiguration 的已知 JSON 字段名集合。
var knownAuthnConfigKeys = map[string]struct{}{
	"authnMethod":                        {},
	"identityType":                       {},
	"clientSecretEnvVarName":             {},
	"privateKeyEnvVarName":               {},
	"applicationFederatedCredentialName": {},
	"clientDeployEnvironment":            {},
	"oidcTokenFilePath":                  {},
	"oidcTokenFilePathEnvVarName":        {},
	"clientX509Certificate":              {},
	"x509CertChains":                     {},
	"pluginName":                         {},
	"humanAuthenticateClientId":          {},
}

// knownHttpConfigKeys HttpConfiguration 的已知 JSON 字段名集合（含旧 tag 兼容）。
var knownHttpConfigKeys = map[string]struct{}{
	"connectTimeout":      {},
	"readTimeout":         {},
	"unsafeIgnoreSslCert": {},
	"unsafeIgnoreSSLCert": {}, // 旧 tag, 保留兼容
}

// warnUnknownConfigKeys 探测 JSON 配置中的未知键并打 WARN。
//
// 实现方式：用 json.Decoder + DisallowUnknownFields 做一次探测解码。
// 如果命中未知键，Go 的 json 包会返回形如 `json: unknown field "xxx"` 的错误，
// 从中提取字段名后做 Levenshtein "did you mean" 建议并打 WARN。
// 探测失败不影响实际加载（实际加载已在上方用 json.Unmarshal 完成）。
func warnUnknownConfigKeys(data []byte, filePath string) {
	// 顶层探测
	probeAndWarn(data, filePath, "", knownTopLevelConfigKeys)

	// 嵌套 authnConfiguration 探测
	if rawAuthn := extractNestedObject(data, "authnConfiguration"); rawAuthn != nil {
		probeAndWarn(rawAuthn, filePath, "authnConfiguration.", knownAuthnConfigKeys)
	}

	// 嵌套 httpConfiguration 探测
	if rawHttp := extractNestedObject(data, "httpConfiguration"); rawHttp != nil {
		probeAndWarn(rawHttp, filePath, "httpConfiguration.", knownHttpConfigKeys)
	}
}

// probeAndWarn 用 DisallowUnknownFields 探测 unknown keys 并逐个打 WARN。
// prefix 用于日志消息中的字段名前缀（如 "authnConfiguration."）。
func probeAndWarn(data []byte, filePath, prefix string, knownKeys map[string]struct{}) {
	// 逐个收集未知键，而非遇到第一个就停（DisallowUnknownFields 遇到第一个就返回），
	// 因此用 map[string]json.RawMessage 手动遍历。
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return // JSON 已在上方验证过，这里不会失败；失败则静默跳过
	}
	for key := range raw {
		if _, ok := knownKeys[key]; ok {
			continue
		}
		fullKey := prefix + key
		suggestion := suggestClosestKey(key, knownKeys)
		msg := "unknown config key \"" + fullKey + "\" in " + filePath
		if suggestion != "" {
			msg += "; did you mean \"" + prefix + suggestion + "\"?"
		}
		logger.Default().Warn(context.Background(), msg,
			"event", "config.unknownKey", "key", fullKey)
	}
}

// extractNestedObject 从顶层 JSON 中提取指定嵌套对象的 raw bytes。
func extractNestedObject(data []byte, field string) json.RawMessage {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return nil
	}
	nested, ok := top[field]
	if !ok {
		return nil
	}
	// 确保 nested 是一个对象（不是 null / 字符串等）
	var test map[string]json.RawMessage
	if err := json.Unmarshal(nested, &test); err != nil {
		return nil
	}
	return nested
}

// suggestClosestKey 返回与 unknown key 编辑距离最近的已知 key（距离 ≤ 3 时才建议，避免噪声）。
func suggestClosestKey(unknown string, knownKeys map[string]struct{}) string {
	best := ""
	bestDist := 4 // 上界：距离 > 3 不建议
	for k := range knownKeys {
		d := levenshtein(unknown, k)
		if d < bestDist {
			bestDist = d
			best = k
		}
	}
	return best
}

// levenshtein 计算两个字符串的 Levenshtein 编辑距离。
func levenshtein(a, b string) int {
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	// 滚动数组：只用前一行 + 当前行
	prev := make([]int, lb+1)
	curr := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			curr[j] = min3(prev[j]+1, curr[j-1]+1, prev[j-1]+cost)
		}
		prev, curr = curr, prev
	}
	return prev[lb]
}

func min3(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}
