// Package slog 把标准库 log/slog.Logger 适配为 SDK 的 logger.Logger 接口。
//
// 这是 SDK 日志三层结构的最外层：主模块只定义 logger.Logger 接口，
// 真正的落地实现放在本嵌套 module 中。接入方这样使用：
//
//	import "github.com/cloud-idaas/idaas-go-core-sdk/logger/adapters/slog"
//
//	client, _ := idaas.NewClient(cfg, idaas.WithLogger(slogadapter.New(slog.Default())))
//
// 为什么要独立 module:log/slog 是 Go 1.21 stdlib,而 SDK 主模块下限锁定
// 1.18+。带自己 go.mod 的子目录不参与主模块构建图,因此本 module 可以声明
// go 1.21 而不抬高主模块下限。
//
// 健壮性约定(与 logger 包一致):
// - kv 长度为奇数时不 panic,由 logger.NormalizeKV 补 "!BADKEY";
// - 敏感 key 的 value 经 logger.RedactKV 强制脱敏;
// - 适配器除格式化外不对 kv 二次求值;
// - 日志失败不影响主流程。
package slog

import (
	"context"
	"log/slog"

	sdklog "github.com/cloud-idaas/idaas-go-core-sdk/logger"
)

// Adapter 将 *slog.Logger 包装为 sdklog.Logger。
//
// 实现了 sdklog.Logger 四个方法,同时实现 sdklog.LevelEnabler,
// 使 SDK 在构造昂贵日志参数前可先做级别判断。
type Adapter struct {
	slog *slog.Logger
}

// New 创建一个基于 *slog.Logger 的 sdklog.Logger。
//
// 传入 nil 时回退到 slog.Default(),避免空指针。调用方通常在进程启动阶段
// 传入自己构造的 *slog.Logger(slog.New(handler)),SDK 不接管其生命周期。
func New(slogLogger *slog.Logger) *Adapter {
	if slogLogger == nil {
		slogLogger = slog.Default()
	}
	return &Adapter{slog: slogLogger}
}

// 编译期断言:*Adapter 同时满足 sdklog.Logger 与 sdklog.LevelEnabler。
var (
	_ sdklog.Logger       = (*Adapter)(nil)
	_ sdklog.LevelEnabler = (*Adapter)(nil)
)

func (a *Adapter) Debug(ctx context.Context, msg string, kv ...interface{}) {
	a.slog.DebugContext(ctx, msg, toSlogArgs(sdklog.RedactKV(kv))...)
}

func (a *Adapter) Info(ctx context.Context, msg string, kv ...interface{}) {
	a.slog.InfoContext(ctx, msg, toSlogArgs(sdklog.RedactKV(kv))...)
}

func (a *Adapter) Warn(ctx context.Context, msg string, kv ...interface{}) {
	a.slog.WarnContext(ctx, msg, toSlogArgs(sdklog.RedactKV(kv))...)
}

func (a *Adapter) Error(ctx context.Context, msg string, kv ...interface{}) {
	a.slog.ErrorContext(ctx, msg, toSlogArgs(sdklog.RedactKV(kv))...)
}

// Enabled 实现 sdklog.LevelEnabler.Enabled。
//
// 将 SDK 的 Level 映射到 slog.Level 后委托给底层 *slog.Logger.Enabled,
// 使 SDK 能在构造昂贵参数前跳过被禁用的级别。
func (a *Adapter) Enabled(ctx context.Context, level sdklog.Level) bool {
	return a.slog.Enabled(ctx, toSlogLevel(level))
}

// toSlogLevel 把 SDK Level 映射到 slog.Level,与 logger.go 中的常量对齐。
func toSlogLevel(level sdklog.Level) slog.Level {
	switch {
	case level < sdklog.LevelInfo:
		return slog.LevelDebug
	case level < sdklog.LevelWarn:
		return slog.LevelInfo
	case level < sdklog.LevelError:
		return slog.LevelWarn
	default:
		return slog.LevelError
	}
}

// toSlogArgs 把归一化后的 []interface{} kv 转为 slog 接受的 []any。
//
// RedactKV 已保证:kv 为偶数长度、key 恒为 string,这里直接断言即可,
// 不会再触发 panic。返回新切片而非原地转换,避免持有调用方的底层数组。
func toSlogArgs(kv []interface{}) []any {
	if len(kv) == 0 {
		return nil
	}
	out := make([]any, len(kv))
	for i, v := range kv {
		out[i] = v
	}
	return out
}
