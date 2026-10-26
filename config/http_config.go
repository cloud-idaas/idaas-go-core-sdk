package config

import (
	"context"
	"encoding/json"

	"github.com/cloud-idaas/idaas-go-core-sdk/constants"
	"github.com/cloud-idaas/idaas-go-core-sdk/logger"
)

// HttpConfiguration HTTP 配置结构体
//
// JSON tag 由 unsafeIgnoreSSLCert 改为 unsafeIgnoreSslCert，
// 与 Java / Python SDK 对齐（跨语言配置文件可移植）。
// 旧 tag 仍可反序列化，但命中时打 WARN 提示迁移（见 UnmarshalJSON）。
//
// ConnectTimeout / ReadTimeout 的 JSON tag 移除 omitempty，
// 使 0 值在 JSON round-trip 中被保留（"显式 0"与"未设置"可区分）。
// 0 值在 Defaulting 阶段被替换为默认值 5000/10000（见 ApplyDefaults）。
type HttpConfiguration struct {
	ConnectTimeout      int  `json:"connectTimeout"` // 毫秒，0 = 未设置（Defaulting 阶段补默认 5000）
	ReadTimeout         int  `json:"readTimeout"`    // 毫秒，0 = 未设置（Defaulting 阶段补默认 10000）
	UnsafeIgnoreSSLCert bool `json:"unsafeIgnoreSslCert,omitempty"`
}

// DefaultHttpConfiguration 返回带默认值的 HTTP 配置。
//
// 默认值与 Java / Python SDK 对齐：5000ms 连接 / 10000ms 读取 / 证书校验开启。
func DefaultHttpConfiguration() *HttpConfiguration {
	return &HttpConfiguration{
		ConnectTimeout:      constants.DefaultConnectTimeoutMs,
		ReadTimeout:         constants.DefaultReadTimeoutMs,
		UnsafeIgnoreSSLCert: false,
	}
}

// ApplyDefaults 对未设置（零值）的字段填充默认值。
//
// 在 config 生命周期的 Defaulting 阶段调用（Load → Defaulting → Normalize → Validate）。
// 调用方已显式设置非零值时保留原值。
func (h *HttpConfiguration) ApplyDefaults() {
	if h.ConnectTimeout == 0 {
		h.ConnectTimeout = constants.DefaultConnectTimeoutMs
	}
	if h.ReadTimeout == 0 {
		h.ReadTimeout = constants.DefaultReadTimeoutMs
	}
}

// httpConfigurationAlias 用于 UnmarshalJSON 时先解码到 alias（tag 全部为 string），
// 再手动赋值，避免二次 UnmarshalJSON 递归。
type httpConfigurationAlias struct {
	ConnectTimeout      int             `json:"connectTimeout"`
	ReadTimeout         int             `json:"readTimeout"`
	UnsafeIgnoreSSLCert json.RawMessage `json:"unsafeIgnoreSslCert,omitempty"`
	// 旧 tag：unsafeIgnoreSSLCert（大小写不同），命中时打 WARN 提示迁移。
	LegacyUnsafeIgnoreSSLCert json.RawMessage `json:"unsafeIgnoreSSLCert,omitempty"`
}

// UnmarshalJSON 实现 的双向兼容反序列化。
//
// 同时接受新旧两个 key（unsafeIgnoreSslCert / unsafeIgnoreSSLCert），
// 命中旧 key 时打 WARN 提示迁移。两个 key 同时存在时以新 key 为准。
func (h *HttpConfiguration) UnmarshalJSON(data []byte) error {
	var alias httpConfigurationAlias
	if err := json.Unmarshal(data, &alias); err != nil {
		return err
	}

	h.ConnectTimeout = alias.ConnectTimeout
	h.ReadTimeout = alias.ReadTimeout

	// 新 tag 优先
	if len(alias.UnsafeIgnoreSSLCert) > 0 {
		var v bool
		if err := json.Unmarshal(alias.UnsafeIgnoreSSLCert, &v); err != nil {
			return err
		}
		h.UnsafeIgnoreSSLCert = v
	} else if len(alias.LegacyUnsafeIgnoreSSLCert) > 0 {
		// 旧 tag 命中：打 WARN 提示迁移
		logger.Default().Warn(context.Background(),
			"config key 'unsafeIgnoreSSLCert' is deprecated, use 'unsafeIgnoreSslCert' instead",
			"event", "config.deprecatedKey",
			"key", "unsafeIgnoreSSLCert",
			"replacement", "unsafeIgnoreSslCert",
		)
		var v bool
		if err := json.Unmarshal(alias.LegacyUnsafeIgnoreSSLCert, &v); err != nil {
			return err
		}
		h.UnsafeIgnoreSSLCert = v
	}

	return nil
}
