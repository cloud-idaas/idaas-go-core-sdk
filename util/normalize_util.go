package util

import (
	"fmt"
	"net/url"
	"strings"
)

// NormalizeEndpoint 归一化 endpoint。
//
// 等价于 NormalizeEndpointWithSecurity(endpoint, false) — 默认安全：
// 裸 host 补全为 https://host，http:// 无条件提升为 https://。
func NormalizeEndpoint(endpoint string) string {
	return NormalizeEndpointWithSecurity(endpoint, false)
}

// NormalizeEndpointWithSecurity 归一化 endpoint，可控制是否允许明文 http://。
//  1. TrimSpace——配置/环境变量里的尾随换行是最常见的"看不见的错误"；
//  2. 裸 host（不含 "://"）补全为 https://host——与 Java/Python 对齐：存量配置/官方模板/
//     README 示例的 POP 端点均为裸 host 形态，三语言须接受同一份配置，补全只指向 https；
//  3. allowInsecure=false 时 http:// 提升为 https://（大小写无关）；allowInsecure=true 时
//     保留 http://，使逃生舱对文件加载的配置也生效（旧实现无条件提升，validator 看到的已是
//     https://，逃生舱仅对 env 加载有效）。
//
// 不负责拒绝输入：带非法 scheme 的（ftp://、ws://）原样透传，由 ConfigValidator 统一报错。
func NormalizeEndpointWithSecurity(endpoint string, allowInsecure bool) string {
	trimmed := strings.TrimSpace(endpoint)
	if trimmed == "" {
		return trimmed
	}
	if !strings.Contains(trimmed, "://") {
		// 裸 host：自动补 https://（与 Java/Python SDK 行为对齐）。
		return httpsSchemePrefix + trimmed
	}
	if !allowInsecure && len(trimmed) >= len(httpScheme) && strings.EqualFold(trimmed[:len(httpScheme)], httpScheme) {
		return httpsSchemePrefix + trimmed[len(httpScheme):]
	}
	return trimmed
}

// httpsSchemePrefix https scheme 前缀，补全 / 提升时统一使用。
const httpsSchemePrefix = "https://"

// httpScheme 明文 http 的 scheme 前缀，仅供 NormalizeEndpoint 做大小写无关比较使用。
const httpScheme = "http://"

// SanitizeEndpointForLog 从 endpoint URL 字符串中剥离 userinfo、query、fragment,
// 仅保留 scheme://host/path,用于日志输出。解析失败时返回安全占位符。
//
// 防止嵌入 URL 的凭证(如 https://user:secret@host/token?access_token=x)
// 被记录到日志。提取到 util 使 config.NormalizeEndpoints 与 factory 共享同一实现,
// 避免同一字段出现 config 不脱敏、factory 脱敏两条不一致路径,消除按 key 名脱敏
// 覆盖不到的 userinfo 泄露面。
func SanitizeEndpointForLog(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u == nil {
		return "<unparseable>"
	}
	// 仅保留 scheme://host/path,丢弃 User / RawQuery / Fragment。
	return u.Scheme + "://" + u.Host + u.Path
}

// ExtractUrlOrigin 提取 URL 的 origin（scheme://host[:port]），丢弃 path/query/fragment。
// 与浏览器 location.origin / RFC 6454 origin 一致：
//
//	https://idaas.example.com/api/v2/oauth2 -> https://idaas.example.com
//	https://idaas.example.com:8443/x?y=1#z -> https://idaas.example.com:8443
//	https://idaas.example.com -> https://idaas.example.com
//
// 要求 rawUrl 非空、可被 net/url.Parse 解析、scheme 与 host 均非空（绝对 URL）。
func ExtractUrlOrigin(rawUrl string) (string, error) {
	if rawUrl == "" {
		return "", fmt.Errorf("url is empty")
	}
	parsed, err := url.Parse(rawUrl)
	if err != nil {
		return "", fmt.Errorf("invalid url %q: %w", rawUrl, err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("url %q must be absolute (scheme://host required)", rawUrl)
	}
	return parsed.Scheme + "://" + parsed.Host, nil
}
