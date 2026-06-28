package util

import (
	"fmt"
	"net/url"
	"strings"
)

// NormalizeEndpoint 归一化 endpoint，将 http 转换为 https (§8.6)
func NormalizeEndpoint(endpoint string) string {
	if strings.HasPrefix(endpoint, "http://") {
		return "https://" + endpoint[7:]
	}
	return endpoint
}

// ExtractUrlOrigin 提取 URL 的 origin（scheme://host[:port]），丢弃 path / query / fragment
//
// 与浏览器 location.origin / RFC 6454 origin 概念一致：
//
//	https://idaas.example.com/api/v2/oauth2  -> https://idaas.example.com
//	https://idaas.example.com:8443/x?y=1#z   -> https://idaas.example.com:8443
//	https://idaas.example.com                -> https://idaas.example.com
//
// 校验规则：
//   - rawUrl 不能为空
//   - 必须能被 net/url.Parse 解析
//   - scheme 与 host 都必须非空（即必须是绝对 URL）
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
