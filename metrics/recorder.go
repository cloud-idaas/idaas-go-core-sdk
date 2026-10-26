// Package metrics 定义 SDK 的可观测性指标接口。
//
// beta 阶段仅占位,默认使用 NoopRecorder(全空实现)。
// GA 阶段接入方可实现本接口,把 SDK 内部指标桥接到 Prometheus /
// OpenTelemetry / 阿里云监控等后端。
//
// 设计原则:
// - 所有方法绝不 panic、绝不返回 error(指标失败不能影响业务);
// - 所有方法并发安全;
// - 标签为固定枚举,避免高基数标签导致指标存储爆炸。
package metrics

import (
	"context"
	"time"
)

// Recorder 是 SDK 内部指标的接收接口。
//
// 方法语义:
// - RecordTokenRefresh: 记录一次凭证刷新,含耗时与成功/失败结果;
// - RecordTokenPrefetch: 记录一次后台预取;
// - RecordCacheHit / RecordCacheMiss: 记录缓存命中/未命中;
// - RecordDegradation: 记录进入/退出降级模式;
// - RecordHttpRequest: 记录一次 HTTP 请求,含状态码与耗时。
//
// GA 阶段才接入行为,beta 阶段用 NoopRecorder。
//
// Experimental:beta 阶段接口已定义(本类型 + NoopRecorder),但既无公开注入点、
// 热路径也不调用 Recorder —— 即 SDK 当前恒用 NoopRecorder(全空实现),任何
// 自定义 Recorder 实现都无法被 SDK 触发(dead hook)。GA 阶段补公开注入 builder +
// 热点埋点(刷新成功/失败、缓存命中/未中、HTTP 请求)后,Recorder 才会被真正
// 调用。beta 阶段保留接口是为 GA 埋点接入时签名稳定(向前兼容)。
type Recorder interface {
	RecordTokenRefresh(ctx context.Context, success bool, duration time.Duration)
	RecordTokenPrefetch(ctx context.Context, success bool, duration time.Duration)
	RecordCacheHit(ctx context.Context, key string)
	RecordCacheMiss(ctx context.Context, key string)
	RecordDegradation(ctx context.Context, entered bool)
	RecordHttpRequest(ctx context.Context, method, endpoint string, statusCode int, duration time.Duration)
}

// noopRecorder 全空实现的 Recorder,不做任何记录。
type noopRecorder struct{}

func (noopRecorder) RecordTokenRefresh(context.Context, bool, time.Duration)               {}
func (noopRecorder) RecordTokenPrefetch(context.Context, bool, time.Duration)              {}
func (noopRecorder) RecordCacheHit(context.Context, string)                                {}
func (noopRecorder) RecordCacheMiss(context.Context, string)                               {}
func (noopRecorder) RecordDegradation(context.Context, bool)                               {}
func (noopRecorder) RecordHttpRequest(context.Context, string, string, int, time.Duration) {}

// NoopRecorder 返回一个全空实现的 Recorder。
// 未注入 Recorder 时 SDK 使用此实例,确保所有调用点无需 nil 检查。
func NoopRecorder() Recorder { return noopRecorder{} }
