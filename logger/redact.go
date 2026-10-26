package logger

import (
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"regexp"
	"strconv"
	"strings"
)

// redactPrefixLen 脱敏后保留的明文前缀长度（按 rune 计，避免截断多字节字符）。
const redactPrefixLen = 6

// Redact 返回敏感字符串的脱敏形式，用于日志输出。
//
// 形如：eyJhbG***(len=842,sha256=1a2b3c4d)
//
// 之所以保留前缀与摘要而非整体替换为 "***"：
// - 前缀让人能区分"token 格式不对"与"token 是对的但过期了"；
// - 长度 + SHA256 前 8 位让同一条凭证在多行日志中可关联比对，
// 同时不足以反推原文（SHA256 无前像攻击可行性，且只暴露 32 bit）。
//
// 短串（rune 长度 <= redactPrefixLen）不保留任何明文前缀，避免泄露
// 密码等短敏感值（如 "abc123" 或 2 字符 token）。长度仍输出用于日志关联。
// 短串也不暴露 sha256 摘要——32 bit 对短 keyspace (如 6 位 user_code
// 仅 10^6 种) 可在秒级暴力枚举还原原文，摘要反而成为泄露通道。
func Redact(s string) string {
	if s == "" {
		return ""
	}

	runes := []rune(s)
	// 仅当值足够长时保留前缀与摘要；短值（len <= redactPrefixLen）暴露全部
	// 字符等价于不脱敏，因此 prefix 置空。短值也不暴露 sha256。
	prefix := ""
	digest := ""
	if len(runes) > redactPrefixLen {
		prefix = string(runes[:redactPrefixLen])
		sum := sha256.Sum256([]byte(s))
		digest = hex.EncodeToString(sum[:])[:8]
	}
	out := prefix + "***(len=" + strconv.Itoa(len(s))
	if digest != "" {
		out += ",sha256=" + digest
	}
	return out + ")"
}

// sensitiveKeys 需要强制脱敏的日志 key（小写、去分隔符后比较）。
//
// 覆盖 OAuth2 / OIDC 全部凭证载体以及本 SDK 自身的认证材料。
var sensitiveKeys = map[string]struct{}{
	"accesstoken":     {},
	"idtoken":         {},
	"refreshtoken":    {},
	"subjecttoken":    {},
	"actortoken":      {},
	"clientsecret":    {},
	"clientassertion": {},
	"privatekey":      {},
	"secret":          {},
	"password":        {},
	"authorization":   {},
	"credential":      {},
	"devicecode":      {},
	"usercode":        {},
	"code":            {},
	"token":           {},
}

// IsSensitiveKey 判断某个日志 key 是否承载敏感信息。
//
// 比较时忽略大小写与 "_"/"-"/"." 分隔符，因此 "access_token"、"accessToken"、
// "access-token" 会被同等识别。
func IsSensitiveKey(key string) bool {
	normalized := strings.Map(func(r rune) rune {
		switch r {
		case '_', '-', '.', ' ':
			return -1
		}
		if r >= 'A' && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return r
	}, key)
	_, ok := sensitiveKeys[normalized]
	return ok
}

// jwtValuePattern 匹配 JWT token(以 eyJ 开头的三段 base64url)。
// 与 errors.jwtPattern 同形,用于 logger 层的值形态兜底脱敏(errors 包不能被
// logger 引入,各自保留一份单行正则,与 truncateForLog/util.TruncateForError
// 的既有重复先例一致)。
var jwtValuePattern = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*`)

// looksLikeJWT 判断字符串是否整体是一个 JWT(以 eyJ 起始且命中三段结构)。
// 要求整串起始即 JWT,避免误伤 merely 含有 JWT 片段的较长文本。
func looksLikeJWT(s string) bool {
	return strings.HasPrefix(s, "eyJ") && jwtValuePattern.MatchString(s)
}

// RedactKV 对 kv 序列做归一化 + 强制脱敏：
// 凡 key 命中 IsSensitiveKey 且 value 为 string / fmt.Stringer 的，
// 一律替换为 Redact(value)；非字符串值替换为固定占位符。
//
// SDK 内部所有带凭证字段的日志调用都必须经过本函数，
// 以避免"某处漏写脱敏"导致凭证进入宿主应用的日志文件。
func RedactKV(kv []interface{}) []interface{} {
	kv = NormalizeKV(kv)
	for i := 0; i+1 < len(kv); i += 2 {
		key, ok := kv[i].(string)
		if !ok || !IsSensitiveKey(key) {
			continue
		}
		switch v := kv[i+1].(type) {
		case nil:
			// 保持 nil，不暴露任何信息
		case string:
			kv[i+1] = Redact(v)
		case interface{ String() string }:
			// typed-nil 指针（如 (*url.URL)(nil)）会匹配此 case，
			// 但调用 v.String() 在 nil receiver 上会 panic。
			// 用 reflect 检测 typed-nil，输出固定占位符而非调用 String()。
			rv := reflect.ValueOf(v)
			if rv.Kind() == reflect.Ptr && rv.IsNil() {
				kv[i+1] = "<nil>"
			} else {
				kv[i+1] = Redact(v.String())
			}
		default:
			kv[i+1] = "***"
		}
	}
	// 值形态纵深防御:按 key 名脱敏只能覆盖已知敏感 key;若凭证出现在
	// 非敏感 key 下(如 "debug_info"/"payload"/"body"),键名匹配会漏掉。
	// 对非敏感 key 的字符串值额外检测 JWT 形态并脱敏,补齐"未知 key 泄露"这一面。
	// 仅在值整体是 JWT(eyJ 起始)时触发,避免误伤仅含 JWT 片段的普通文本。
	for i := 0; i+1 < len(kv); i += 2 {
		key, _ := kv[i].(string)
		if key != "" && IsSensitiveKey(key) {
			continue // 已在上方按 key 名脱敏
		}
		if s, ok := kv[i+1].(string); ok && looksLikeJWT(s) {
			kv[i+1] = Redact(s)
		}
	}
	return kv
}
