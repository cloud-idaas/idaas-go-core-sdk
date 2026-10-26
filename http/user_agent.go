package http

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
)

const (
	// sdkName UA 中的产品标识，与发布的 module 名保持一致。
	sdkName = "cloud-idaas-go-sdk"

	// modulePath 是 go.mod 中声明的 module 路径，用于在
	// debug.ReadBuildInfo().Deps 中匹配本 SDK 的依赖版本。
	modulePath = "github.com/cloud-idaas/idaas-go-core-sdk"
)

// sdkVersion SDK 版本号，由发布流水线通过 -ldflags 注入：
//
//	go build -ldflags "-X github.com/cloud-idaas/idaas-go-core-sdk/http.sdkVersion=$(git describe --tags)"
//
// 必须是 var 而不是 const —— `-X` 只能改写字符串变量，常量会被编译期内联，注入静默失效。
//
// 源码里的兜底值刻意取 "0.0.0-dev" 这种一眼可辨的占位值：
// 此处曾硬编码 "1.0.0"，而实际发布的是 v0.1.0-alpha.3，一旦接通就会向服务端**谎报版本**，
// 破坏服务端按版本灰度与排障的能力——比不发 UA 更糟。CI 中有一条检查禁止该值
// 匹配 ^\d+\.\d+\.\d+$，防止有人"顺手改回真版本号"。
//
// 库消费者（go get）的场景下 -ldflags 不会注入，sdkVersion 保持 "0.0.0-dev"。
// 此时通过 resolveSdkVersion() 从 debug.ReadBuildInfo().Deps 读取消费者二进制中
// 记录的本 SDK 模块版本（Go 1.18 起 Deps 包含依赖模块版本）。
var sdkVersion = "0.0.0-dev"

const defaultSdkVersion = "0.0.0-dev"

// resolvedVersion 缓存 resolveSdkVersion 的结果，避免每次 BuildUserAgent 都调用 debug.ReadBuildInfo。
var (
	resolvedVersion string
	resolveOnce     sync.Once
)

// resolveSdkVersion 按优先级解析 SDK 版本号：
//  1. -ldflags 注入的 sdkVersion（非空且非默认占位值）——显式注入优先于自动推断
//  2. debug.ReadBuildInfo().Deps 中匹配 modulePath 的依赖版本（库消费者场景）
//  3. "0.0.0-dev" 兜底
//
// 解析顺序为 ldflags 注入值优先,再查 Deps:当 samples 以 require v0.0.0 + replace ../
// 方式构建时,Deps 记录的版本是 v0.0.0,若先于 ldflags 注入的真实版本被返回,
// 会导致发布的 sample 二进制 User-Agent 显示 v0.0.0。
func resolveSdkVersion() string {
	resolveOnce.Do(func() {
		// 1. -ldflags 注入的值（非默认占位值时视为有效注入）。
		if sdkVersion != "" && sdkVersion != defaultSdkVersion {
			resolvedVersion = sdkVersion
			return
		}

		// 2. 从消费者二进制的依赖列表中查找本 SDK 模块版本。
		if info, ok := debug.ReadBuildInfo(); ok {
			for _, dep := range info.Deps {
				if dep.Path == modulePath {
					v := strings.TrimSpace(dep.Version)
					if v != "" && v != "(devel)" && v != defaultSdkVersion {
						resolvedVersion = v
						return
					}
					break
				}
			}
		}

		// 3. 兜底。
		resolvedVersion = defaultSdkVersion
	})
	return resolvedVersion
}

// GetSdkVersion 返回当前 SDK 版本号。
//
// 解析口径与 BuildUserAgent 一致:优先 -ldflags 注入值,其次 debug.ReadBuildInfo
// 记录的消费者依赖版本,最后 "0.0.0-dev" 兜底。供宿主在日志/issue 模板中引用
// (与 .github/ISSUE_TEMPLATE/bug_report.yml 的 "SDK version" 字段对齐),
// 避免模板引用了不存在的 API。
//
// Experimental:beta 阶段接入;GA 前若版本解析口径调整会保持返回 string 不变。
func GetSdkVersion() string {
	return resolveSdkVersion()
}

// BuildUserAgent 构建 User-Agent 字符串。
//
// 格式：cloud-idaas-go-sdk/<version> (<goos>; <goarch>) go/<goversion>
// 例如：cloud-idaas-go-sdk/0.1.0 (linux; amd64) go/go1.21.5
//
// 带上 Go 版本是为了让服务端能在出现"仅某个 Go 版本复现"的问题时快速定位
// （典型如 TLS 栈、http2 行为随 Go 版本变化）。UA 不含任何用户标识或凭证信息。
func BuildUserAgent() string {
	return fmt.Sprintf("%s/%s (%s; %s) go/%s",
		sdkName, resolveSdkVersion(), runtime.GOOS, runtime.GOARCH, runtime.Version())
}
