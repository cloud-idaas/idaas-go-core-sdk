package logger

import "context"

// nopLogger 完全静默的 Logger 实现。
type nopLogger struct{}

func (nopLogger) Debug(context.Context, string, ...interface{}) {}
func (nopLogger) Info(context.Context, string, ...interface{})  {}
func (nopLogger) Warn(context.Context, string, ...interface{})  {}
func (nopLogger) Error(context.Context, string, ...interface{}) {}

// Enabled 恒为 false，使调用方可以跳过所有日志参数的构造开销。
func (nopLogger) Enabled(context.Context, Level) bool { return false }

var nop Logger = nopLogger{}

// Nop 返回一个完全静默的 Logger。
//
// 与默认 Logger 的区别：Nop 表示"我明确不需要任何 SDK 日志"，
// 不会打印未配置提示；默认 Logger 表示"尚未配置"，首次 Warn/Error 会提示一次。
func Nop() Logger { return nop }
