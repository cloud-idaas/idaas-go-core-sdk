// Package logger 定义 SDK 的最小日志抽象。
// 设计约束：
// 1. 零第三方依赖、仅 Go 1.18 标准库——本包是主模块一部分，不能因日志把 Go 下限抬到 1.21（log/slog 引入版本）。
// 2. 不提供"内置实现+格式化输出"，落地实现放在 logger/adapters/* 独立 module（库不抢占宿主日志栈）。
// 3. 默认实现非纯 noop：Debug/Info 丢弃，Warn/Error 向 stderr 打一次性提示，避免"SDK 出错却完全静默"的排障黑洞。
// 所有方法带 ctx 首参，便于适配器从 ctx 取 trace/request id。
package logger

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"sync"
)

// Level 日志级别。取值与 log/slog 保持一致，便于适配器做 1:1 映射。
type Level int

const (
	LevelDebug Level = -4
	LevelInfo  Level = 0
	LevelWarn  Level = 4
	LevelError Level = 8
)

// String 返回级别名称。
func (l Level) String() string {
	switch {
	case l < LevelInfo:
		return "DEBUG"
	case l < LevelWarn:
		return "INFO"
	case l < LevelError:
		return "WARN"
	default:
		return "ERROR"
	}
}

// Logger 是 SDK 对外暴露的日志接口。
//
// kv 为交替出现的 key/value 序列（key 必须是 string）。实现方必须保证：
// 即使 kv 长度为奇数或 key 不是 string，也绝不 panic —— 日志永远不能
// 成为业务链路的故障源。可使用 NormalizeKV 完成这一归一化。
//
// 兼容性提示：本接口未来若需新增方法，将通过新增独立接口 + 类型断言的
// 方式演进（如 LevelEnabler），不会直接修改本接口，以免破坏外部实现者。
type Logger interface {
	Debug(ctx context.Context, msg string, kv ...interface{})
	Info(ctx context.Context, msg string, kv ...interface{})
	Warn(ctx context.Context, msg string, kv ...interface{})
	Error(ctx context.Context, msg string, kv ...interface{})
}

// LevelEnabler 是可选接口。实现了该接口的 Logger 可以让 SDK 在构造
// 昂贵的日志参数（如序列化、脱敏哈希计算）之前先做级别判断。
type LevelEnabler interface {
	Enabled(ctx context.Context, level Level) bool
}

// Enabled 判断指定 logger 在给定级别下是否需要记录日志。
// 未实现 LevelEnabler 的 Logger 一律视为开启（保守策略，宁可多算不可漏记）。
func Enabled(ctx context.Context, l Logger, level Level) bool {
	if l == nil {
		return false
	}
	if e, ok := l.(LevelEnabler); ok {
		return e.Enabled(ctx, level)
	}
	return true
}

// badKeyPlaceholder 当 kv 序列不合法时用于占位，确保日志调用永不 panic。
const badKeyPlaceholder = "!BADKEY"

// NormalizeKV 将任意 kv 变参归一化为合法的 key/value 交替序列：
// - 长度为奇数时，为最后一个孤立值补上 "!BADKEY" 作为 key；
// - key 不是 string 时，用 "!BADKEY" 替换，原值作为紧随其后的 value 保留。
//
// 适配器实现应在转发给底层日志库之前调用本函数。
func NormalizeKV(kv []interface{}) []interface{} {
	out := make([]interface{}, 0, len(kv)+1)
	for i := 0; i < len(kv); i += 2 {
		if i+1 >= len(kv) {
			out = append(out, badKeyPlaceholder, kv[i])
			break
		}
		if _, ok := kv[i].(string); !ok {
			out = append(out, badKeyPlaceholder, kv[i], badKeyPlaceholder, kv[i+1])
			continue
		}
		out = append(out, kv[i], kv[i+1])
	}
	return out
}

// hintLogger 是未配置日志实现时的默认 Logger。
//
// 行为：Debug/Info 静默丢弃；首次出现 Warn/Error 时向 stderr 打印一条
// 一次性提示（含该条日志内容），此后彻底静默，避免污染宿主应用的输出。
type hintLogger struct {
	once sync.Once
}

const hintBanner = "[cloud-idaas-go-sdk] no logger configured; the SDK reported a problem below. " +
	"Install an adapter (e.g. github.com/cloud-idaas/idaas-go-core-sdk/logger/adapters/slog) " +
	"to receive SDK diagnostics. This notice is printed only once."

func (h *hintLogger) Debug(context.Context, string, ...interface{}) {}
func (h *hintLogger) Info(context.Context, string, ...interface{})  {}

func (h *hintLogger) Warn(_ context.Context, msg string, kv ...interface{}) {
	h.emit(LevelWarn, msg, kv)
}

func (h *hintLogger) Error(_ context.Context, msg string, kv ...interface{}) {
	h.emit(LevelError, msg, kv)
}

func (h *hintLogger) emit(level Level, msg string, kv []interface{}) {
	h.once.Do(func() {
		fmt.Fprintln(os.Stderr, hintBanner)
		fmt.Fprintln(os.Stderr, "[cloud-idaas-go-sdk] "+level.String()+" "+msg+formatKV(kv))
	})
}

// Enabled 让默认 logger 可被探测：Debug/Info 恒为 false，
// 调用方据此跳过昂贵的参数构造。
func (h *hintLogger) Enabled(_ context.Context, level Level) bool {
	return level >= LevelWarn
}

// formatKV 把 kv 序列渲染成 " k=v k=v" 形式，仅用于默认 logger 的一次性提示。
//
// 必须经过 RedactKV 而非仅 NormalizeKV。hintLogger 把首条 Warn/Error
// 原样打到 stderr，若该条恰好携带 access_token / refresh_token / client_secret
// 等字段（SDK 内部日志调用约定经 RedactKV 脱敏，但 adapter 缺失时这条提示
// 是兜底出口），不脱敏会把凭证明文落到终端/容器日志。
// RedactKV 内部已调用 NormalizeKV，归一化与脱敏都覆盖。
func formatKV(kv []interface{}) string {
	kv = RedactKV(kv)
	if len(kv) == 0 {
		return ""
	}
	out := ""
	for i := 0; i+1 < len(kv); i += 2 {
		key, _ := kv[i].(string)
		if key == "" {
			key = badKeyPlaceholder
		}
		out += " " + key + "=" + formatValue(kv[i+1])
	}
	return out
}

func formatValue(v interface{}) string {
	switch t := v.(type) {
	case nil:
		return "<nil>"
	case string:
		return strconv.Quote(t)
	case error:
		return strconv.Quote(t.Error())
	default:
		return fmt.Sprintf("%v", t)
	}
}

var (
	defaultMu sync.RWMutex
	// defaultLogger 为包级默认 Logger。SDK 内部那些拿不到 factory 实例的
	// 组件（如后台预取 goroutine）通过 Default() 取用。
	defaultLogger Logger = &hintLogger{}
)

// Default 返回当前包级默认 Logger，永不返回 nil。
func Default() Logger {
	defaultMu.RLock()
	defer defaultMu.RUnlock()
	return defaultLogger
}

// SetDefault 设置包级默认 Logger。传入 nil 表示恢复为 Nop()
// （显式静默，与"未配置"的一次性提示行为区分开）。
//
// 通常由宿主应用在进程启动阶段调用一次；SDK 自身不会隐式调用。
func SetDefault(l Logger) {
	// (*Adapter)(nil) 是 typed-nil:接口值非 nil(l == nil 为 false),
	// 但底层指针为 nil。存为全局 default 后 Default().Warn() 解引用 nil → panic。
	// 用 reflect 检测 typed-nil,nil 与 typed-nil 均替换为 Nop()。
	if l == nil || isNilLogger(l) {
		l = Nop()
	}
	defaultMu.Lock()
	defaultLogger = l
	defaultMu.Unlock()
}

// isNilLogger 检测 Logger 接口的底层指针是否为 typed-nil。
func isNilLogger(l Logger) bool {
	v := reflect.ValueOf(l)
	return v.Kind() == reflect.Ptr && v.IsNil()
}
