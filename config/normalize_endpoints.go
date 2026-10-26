package config

import (
	"context"

	"github.com/cloud-idaas/idaas-go-core-sdk/logger"
	"github.com/cloud-idaas/idaas-go-core-sdk/util"
)

// NormalizeEndpoints 就地归一化配置中的全部 endpoint。
//
// 与 factory.normalizeEndpoints 行为一致:对裸 hostname 自动补 https://,
// 对 http:// 在非逃生舱模式下提升为 https://。调用方在 Validate 前调用本方法,
// 可避免裸 hostname 因缺 scheme 被 validator 拒绝(factory.Initialize 内部会
// 自动调用,但直接使用 config 包的调用方需要显式调用)。
//
// samples/refresh-token 等直接使用 config 包的调用方:
// LoadWithPriority 不做端点归一化,Validate 会拒绝裸 hostname。
func (c *IDaaSClientConfig) NormalizeEndpoints() {
	allowInsecure := c.AllowInsecureEndpoint

	fields := []struct {
		name string
		ptr  *string
	}{
		{"issuer", &c.IssuerEndpoint},
		{"tokenEndpoint", &c.TokenEndpoint},
		{"deviceAuthorizationEndpoint", &c.DeviceAuthorizationEndpoint},
		{"developerApiEndpoint", &c.DeveloperApiEndpoint},
		{"openApiEndpoint", &c.OpenApiEndpoint},
	}
	for _, f := range fields {
		original := *f.ptr
		normalized := util.NormalizeEndpointWithSecurity(original, allowInsecure)
		if normalized == original {
			continue
		}
		*f.ptr = normalized
		logger.Default().Warn(context.Background(),
			"endpoint normalized",
			"event", "config.normalize", "status", "success",
			"field", f.name,
			"from", util.SanitizeEndpointForLog(original),
			"to", util.SanitizeEndpointForLog(normalized))
	}
}
