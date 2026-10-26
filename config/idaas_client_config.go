package config

import (
	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
)

// 注意：阿里云 IDaaS 官方配置规范中**没有顶层 deployEnvironment 字段**。
// 部署环境字段位于 authnConfiguration.clientDeployEnvironment，
// 仅用于 PKCS7 / OIDC 两种 authnMethod。详见 IdentityAuthenticationConfiguration。
type IDaaSClientConfig struct {
	ClientId                    string `json:"clientId"`
	InstanceId                  string `json:"idaasInstanceId"`
	IssuerEndpoint              string `json:"issuer"`
	TokenEndpoint               string `json:"tokenEndpoint"`
	DeviceAuthorizationEndpoint string `json:"deviceAuthorizationEndpoint,omitempty"`
	DeveloperApiEndpoint        string `json:"developerApiEndpoint,omitempty"`
	OpenApiEndpoint             string `json:"openApiEndpoint,omitempty"`

	AuthnConfiguration *IdentityAuthenticationConfiguration `json:"authnConfiguration,omitempty"`

	HttpConfiguration *HttpConfiguration `json:"httpConfiguration,omitempty"`

	// AllowInsecureEndpoint 逃生门：允许 http:// 端点。
	// 默认 false——所有端点必须 https，明文链路会让 Bearer token / client_secret 裸奔。
	// 设为 true 时：validator 不再拒绝 http:// 端点，但**每次 init 打 WARN**，
	// 且 normalizeEndpoints 仍会尝试 http→https 升级（升级后 https 的不受影响）。
	// 仅限本地联调 / 自签名内网环境使用，生产环境必须保持 false。
	AllowInsecureEndpoint bool `json:"allowInsecureEndpoint,omitempty"`

	Scope string `json:"scope,omitempty"`

	// Experimental: StaleValueBehavior 控制 cache 进入 stale 窗口后的取值策略。
	// beta 阶段已实际接入(非 GA 预留):supplier GetWithContext 的 stale/expired 分支
	// 直接消费此枚举。语义可能在 GA 前调整(如 BLOCK 退避窗口策略,见),故标 Experimental。
	// - BLOCK :expired 阶段不返回旧值(退避窗内返 ErrRefreshInBackoff,窗外同步刷新)
	// - ALLOW :直接返回旧值,后台不刷新(牺牲一致性换可用性)
	// - REFRESH:同步刷新,失败后返回旧值(默认,平衡可用性与一致性)
	// 空值回退 REFRESH,与 beta 阶段各 provider 的硬编码默认一致,向后兼容。
	StaleValueBehavior enums.StaleValueBehavior `json:"staleValueBehavior,omitempty"`

	// —— GA 扩展点预留 ——
	//
	// 以下字段 beta 阶段仅解析(parsable)、不启用(enabled=false 的等价行为),
	// 配置中出现未知值不报错(validator 不校验取值合法性),保持向前兼容。
	// GA 阶段接入实际行为时再补 Validate。StaleValueBehavior 不在此列(已 beta 接入,见上)。

	// FailureMode 控制刷新失败时的降级行为(FAIL_FAST / FAIL_OPEN / FAIL_CLOSED)。
	// beta 阶段:解析后忽略;GA 阶段接入实际降级行为时会映射到 supplier 的 StaleValueBehavior。
	FailureMode enums.FailureMode `json:"failureMode,omitempty"`

	// MetricsEnabled 是否开启 SDK 内部指标上报。
	// beta 阶段:恒为 false,metrics.Recorder 使用 NoopRecorder。
	MetricsEnabled bool `json:"metricsEnabled,omitempty"`

	// LogLevel 覆盖 SDK 内部日志级别(DEBUG / INFO / WARN / ERROR)。
	// beta 阶段:解析后忽略,日志级别由接入方注入的 Logger 自行控制。
	LogLevel string `json:"logLevel,omitempty"`
}
