package util

import "unicode/utf8"

// TruncateForError 把字节切片截断为不超过 max 字节的字符串,用于构造错误消息。
//
// 背景:错误响应体被原样嵌入 error message / 日志时,恶意或故障服务返回的超大响应
// 会撑爆日志与内存。即使 DefaultHttpClient 已用 LimitReader 封顶,
// 在错误消息里仍应截断到合理长度 (建议 512 字节),保留排障所需的前缀信息。
// 截断时追加 "...(truncated)" 标记,使调用方明确知道体被裁剪。
//
// 截断按字节切片,但回退到最近的 UTF-8 码点边界,避免切断多字节序列产生
// 非法 UTF-8 字符串(后续 JSON 序列化/终端渲染会出现替换字符)。
func TruncateForError(b []byte, maxLen int) string {
	if maxLen <= 0 {
		maxLen = 512
	}
	if len(b) <= maxLen {
		return string(b)
	}
	// 回退到完整码点边界:UTF-8 续续字节(10xxxxxx)不可能是 RuneStart,
	// 递减 maxLen 直到落在起始字节上,避免切出半个码点。
	for maxLen > 0 && !utf8.RuneStart(b[maxLen]) {
		maxLen--
	}
	return string(b[:maxLen]) + "...(truncated)"
}
