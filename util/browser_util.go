package util

import (
	"bytes"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/exec"
	"runtime"
)

// allowedBrowserSchemes 是 OpenBrowser 允许打开的 URL scheme 白名单。
// 仅 http/https 是安全的浏览器目标;file:// 可指向本地敏感文件,
// javascript: 可在 rundll32/浏览器上下文执行脚本,均须拒绝。
var allowedBrowserSchemes = map[string]struct{}{
	"http":  {},
	"https": {},
}

// UserCodeHandler 是 Device Code 流程(RFC 8628)展示 user_code 与验证 URI 的回调签名。
// verificationURI 是用户应访问的最佳 URI(IdP 返回 verification_uri_complete 时即该
// 完整 URL,内嵌 user_code 免手输;否则为 bare verification_uri,用户需手输 user_code)。
// userCode 是 IdP 返回的一次性展示码(短生命周期、设计上人类可见),非长生命周期凭证。
//
// 实现职责:把 code/URI 展示给最终用户(CLI 打印 stdout、服务端渲染 web 页等)。
// 可选地调 OpenBrowser 打开浏览器(库边界 side-effect 由宿主决定,SDK 自身不主动打开)。
type UserCodeHandler func(verificationURI, userCode string)

// PrintUserCode 是 Device Code 流程的默认 user_code 展示回调:
// 把 verification URI 与 user_code 打印到 stdout(CLI 约定通道),供最终用户在另一
// 设备完成授权。user_code 是 RFC 8628 一次性短码(设计上人类可见),走 stdout
// 而非结构化日志,避免进入持久化集中式日志后被他人抢在合法用户前完成授权。
//
// 服务端集成(无终端)必须注入自定义 handler 覆盖默认行为(README 声明此宿主义务)。
// 库写 stdout 属 side-effect:默认 stdout 是 CLI 约定通道,服务端必须覆盖。
func PrintUserCode(verificationURI, userCode string) {
	if verificationURI != "" {
		fmt.Fprintln(os.Stdout, "To complete authentication, open this URL:", verificationURI)
	}
	if userCode != "" {
		// "If prompted" 覆盖两种情况:verification_uri_complete 已内嵌 code(浏览器自动填,
		// 此行冗余但无害)与 bare verification_uri(需手输,此行必需)。
		fmt.Fprintln(os.Stdout, "If prompted, enter this code:", userCode)
	}
}

// OpenBrowser 打开浏览器，用于 Device Code 流程。
//
// 入参 url 通常来自 IdP 在 device authorization 响应里返回的
// verification_uri_complete;若 IdP 被攻陷或响应被篡改,该 url 可能是
// file://、javascript: 等危险 scheme,原样交给 xdg-open/open 会执行非预期
// 内容。因此入口先做 scheme 白名单校验,仅放行 http/https。
//
// 失败时返回错误，并把 stderr 内容写入 log 以便排查（cmd.Start 默认
// 只会返回 "exec: xxx: executable file not found"，丢失了真正的 stderr 上下文）。
func OpenBrowser(rawURL string) error {
	// 空 URL 直接拒绝,避免把空串交给 shell 造成歧义。
	if rawURL == "" {
		return fmt.Errorf("open browser: empty url")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		// rawURL 是 IdP 返回的 verification_uri_complete,内含一次性 user_code,
		// 不得出现在错误字符串里(宿主可能把它写进日志,绕过 RedactKV 的 error key)。
		// url.Error.Error() 内嵌完整 rawURL(parse "<rawURL>": <reason>),直接 %w 会
		// 把 user_code 泄漏进 error 字符串;只取底层 reason(urlErr.Err)即可保留排障信息。
		reason := err.Error()
		if urlErr, ok := err.(*url.Error); ok {
			reason = urlErr.Err.Error()
		}
		return fmt.Errorf("open browser: invalid url: %s", reason)
	}
	if _, ok := allowedBrowserSchemes[parsed.Scheme]; !ok {
		// scheme 本身不是敏感数据;rawURL 含 user_code,不得输出。
		return fmt.Errorf("open browser: unsupported scheme %q (only http/https allowed)", parsed.Scheme)
	}

	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("xdg-open", rawURL)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", rawURL)
	case "darwin":
		cmd = exec.Command("open", rawURL)
	default:
		return nil // 不支持的平台，静默忽略
	}

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		// 仅保留 scheme + host 用于排障:rawURL 含一次性 user_code,进 stdlib log 或
		// 返回值的 error 字符串都会绕过 RedactKV(其 sensitive key 列表不含 "error"),
		// 被 central collector / 本机其他用户读到后可抢在合法用户前完成 device 授权。
		redactedURL := parsed.Scheme + "://" + parsed.Host
		if stderr.Len() > 0 {
			log.Printf("[DEBUG] OpenBrowser failed url=%s error=%s stderr=%s", redactedURL, err.Error(), stderr.String())
		}
		return fmt.Errorf("failed to open browser for %s: %w", redactedURL, err)
	}
	return nil
}
