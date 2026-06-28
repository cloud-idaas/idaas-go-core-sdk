package util

import (
	"bytes"
	"fmt"
	"log"
	"os/exec"
	"runtime"
)

// OpenBrowser 打开浏览器，用于 Device Code 流程。
//
// 失败时返回错误，并把 stderr 内容写入 log 以便排查（cmd.Start 默认
// 只会返回 "exec: xxx: executable file not found"，丢失了真正的 stderr 上下文）。
func OpenBrowser(url string) error {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		return nil // 不支持的平台，静默忽略
	}

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		if stderr.Len() > 0 {
			log.Printf("[DEBUG] OpenBrowser failed url=%s error=%s stderr=%s", url, err.Error(), stderr.String())
		}
		return fmt.Errorf("failed to open browser for %s: %v", url, err)
	}
	return nil
}
