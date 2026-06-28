package http

import (
	"fmt"
	"runtime"
)

const (
	sdkName    = "idaas-go-core-sdk"
	sdkVersion = "1.0.0"
)

// BuildUserAgent 构建 User-Agent 字符串 (§9.4)
func BuildUserAgent() string {
	return fmt.Sprintf("%s/%s (%s; %s)", sdkName, sdkVersion, runtime.GOOS, runtime.GOARCH)
}
