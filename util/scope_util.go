package util

import (
	"regexp"
	"sort"
	"strings"

	"github.com/cloud-idaas/idaas-go-core-sdk/constants"
	"github.com/cloud-idaas/idaas-go-core-sdk/errors"
)

// scopePattern 对齐 Java/Python：scope 项须含 "|" 分隔的 audience 与 permission。
var scopePattern = regexp.MustCompile(`^[^|]+\|[^|]+$`)

// SplitScope 拆分 scope 字符串为有序列表。
//
// 做三件事：
// 1. TrimSpace 去首尾空白
// 2. Fields 按空白拆分并去空
// 3. sort.Strings 排序（与 Java/Python 一致，消除多 scope 顺序差异对缓存的影响）
func SplitScope(scope string) []string {
	trimmed := strings.TrimSpace(scope)
	if trimmed == "" {
		return nil
	}
	parts := strings.Fields(trimmed)
	sort.Strings(parts)
	return parts
}

// CanonicalizeScope 返回 scope 的规范化字符串（排序 + 单空格连接）。
//
// 用作缓存 key：同一组 scope 不同输入顺序得到同一 key，修掉
// （多 scope 顺序不同导致重复建 provider / 缓存不共用）。
func CanonicalizeScope(scope string) string {
	return strings.Join(SplitScope(scope), " ")
}

// IsValidScope 判断单个 scope 项是否符合 "audience|permission" 格式。
func IsValidScope(item string) bool {
	return scopePattern.MatchString(item)
}

// ValidateScope 校验 scope 字符串。
//
// 规则：
// - 空 → ConfigError(InvalidScope)
// - 任一项不匹配 scopePattern → ConfigError(InvalidScope)
// - 多于一项的 audience（"|" 前部分不唯一）→ ConfigError(MultipleAudienceNotSupported)
//
// 返回带码的 ConfigError，不再是裸 errors.New。
func ValidateScope(scope string) error {
	scopes := SplitScope(scope)
	if len(scopes) == 0 {
		return errors.NewConfigError(
			constants.InvalidScope,
			"scope cannot be empty",
			nil,
		)
	}

	audienceSet := make(map[string]struct{})
	for _, s := range scopes {
		if !IsValidScope(s) {
			return errors.NewConfigError(
				constants.InvalidScope,
				"invalid scope format: "+s+" (expected: audience|permission)",
				nil,
			)
		}
		aud, _ := ExtractAudience(s)
		audienceSet[aud] = struct{}{}
	}

	if len(audienceSet) > 1 {
		return errors.NewConfigError(
			constants.MultipleAudienceNotSupported,
			"multiple audiences in scope are not supported",
			nil,
		)
	}

	return nil
}

// ExtractAudience 从单个 scope 项中提取 audience。
//
// scope 项格式为 "audience|permission"，取 "|" 左半部分。
// 不再使用 "audience:" 前缀逻辑，与 Java/Python 对齐。
func ExtractAudience(scopeItem string) (string, error) {
	idx := strings.Index(scopeItem, "|")
	if idx < 0 {
		return "", errors.NewConfigError(
			constants.InvalidScope,
			"no audience separator '|' in scope item: "+scopeItem,
			nil,
		)
	}
	return scopeItem[:idx], nil
}

// ExtractAudienceFromScope 从 scope 字符串中提取第一个 audience。
//
// Deprecated: 自 v0.x 起改为 util.ExtractAudience(scopeItem)，后者接收单个
// scope item 而非整 scope 字符串，语义更清晰、避免在多 item 上隐式取第一个。
// 本函数保留为薄壳（与 factory.GetInstance 的 deprecated 薄壳做法一致）：
// 内部按 SplitScope 拆分后对每个 item 调 ExtractAudience，返回第一个成功结果。
//
// 注意：与 master 时代 "audience:" 前缀语义不等价——新格式要求 "audience|permission"
// 管道分隔，旧格式 scope 会返回 InvalidScope 错误（旧格式兼容属 P1 范畴，不在本薄壳处理）。
// 后续将移除，请迁移至 ExtractAudience。
func ExtractAudienceFromScope(scope string) (string, error) {
	for _, item := range SplitScope(scope) {
		if aud, err := ExtractAudience(item); err == nil && aud != "" {
			return aud, nil
		}
	}
	return "", errors.NewConfigError(
		constants.InvalidScope,
		"no audience found in scope",
		nil,
	)
}
