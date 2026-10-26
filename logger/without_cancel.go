package logger

import (
	"context"
	"time"
)

// withoutCancelCtx 继承 parent 的 Value 链但不响应取消。
//
// 这是 Go 1.21 context.WithoutCancel 的 1.18 polyfill。SDK 下限锁定 1.18
// (go.mod),而 1.21 前标准库无 context.WithoutCancel;为不抬高下限,在此手写
// 等价语义并集中维护()。调用点统一为 logger.WithoutCancel(parentCtx)。
//
// 语义对齐 1.21:
//   - Deadline() (time.Time{}, false) —— 无截止时间
//   - Done() nil —— select{<-ctx.Done()} 永久阻塞(永不触发,正确)
//   - Err() nil —— 不视为已取消
//   - Value(key) 透传 parent —— 保留 trace span/requestId 等关联信息
//
// 用途:goroutine 内日志 ctx。worker 的 refresh 操作 ctx 会随 parent 取消而取消,
// 但日志仍须落盘(失败原因/panic 记录),故日志 ctx 与 refresh ctx 解耦——用
// logger.WithoutCancel(baseCtx) 派生,既保留 trace 关联又不被 parent 取消拒记。
// **不得在新 worker 代码里硬编码 context.Background()**。
type withoutCancelCtx struct {
	parent context.Context
}

func (c *withoutCancelCtx) Deadline() (time.Time, bool) { return time.Time{}, false }
func (c *withoutCancelCtx) Done() <-chan struct{}       { return nil }
func (c *withoutCancelCtx) Err() error                  { return nil }
func (c *withoutCancelCtx) Value(key any) any           { return c.parent.Value(key) }
func (c *withoutCancelCtx) String() string {
	return "logger.WithoutCancel(" + contextString(c.parent) + ")"
}

// WithoutCancel 返回继承 parent Value 链但不响应取消的 context.Context
// (1.18 polyfill of context.WithoutCancel)。
//
// 用于 goroutine 内日志:保留 trace span/requestId,不被 parent 取消拒记。
// 详见 [withoutCancelCtx] 文档。
//
// Experimental: beta 阶段语义已稳定(对齐 1.21 context.WithoutCancel),但调用点
// 范围(剩余的 ctx 透传 sweep)在 GA 前会扩展;GA 时若主模块下限抬到 1.21,
// 本函数将改为直接转发 context.WithoutCancel 并保留为兼容别名。
func WithoutCancel(parent context.Context) context.Context {
	if parent == nil {
		// 防御:nil parent 等价 context.Background()——不响应取消、无 Value。
		// 不直接返回 context.Background() 以保持类型可识别(调试/断言)。
		parent = context.Background()
	}
	return &withoutCancelCtx{parent: parent}
}

// contextString 复用 context.Context 的 String 表达,避免引入额外依赖。
// 未导出,仅用于 withoutCancelCtx.String() 调试输出。
func contextString(ctx context.Context) string {
	if s, ok := ctx.(interface{ String() string }); ok {
		return s.String()
	}
	return "context.Context"
}
