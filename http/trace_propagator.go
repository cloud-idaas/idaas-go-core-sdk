package http

import "context"

// HeaderCarrier 是分布式 trace context(W3C TraceContext 的 traceparent/tracestate,
// 或 B3 的 X-B3-TraceId 等)注入出站 HTTP 请求头的载体抽象。
//
// net/http.Header 原生实现 Set/Get,直接满足本接口,无需 adapter:
//
//	c.propagator.Inject(ctx, req.Header)
//
// 与 go.opentelemetry.io/otel/propagation.TextMapCarrier 同构(Set/Get 语义一致),
// 使调用方可用一行 adapter 把 OTel TextMapPropagator 桥接到本接口,而 SDK 不引入
// OTel 依赖(库不绑死框架原则)。
type HeaderCarrier interface {
	Set(key, value string)
	Get(key string) string
}

// TracePropagator 把分布式 trace context 注入到出站 HTTP 请求头。
//
// 由宿主经 factory.WithTracePropagator(或 DefaultHttpClient.WithTracePropagator)
// 注入;nil 表示不注入(beta 默认,零回归)。实现方按 W3C TraceContext / B3 等约定
// 写入对应头。SDK 在 ExecuteContext 发起请求前调用 Inject;不内置任何 OTel 依赖,
// 也不在 SDK 内部制造 trace —— 只透传调用方 ctx 中已有的 trace 上下文。
//
// 与 ctx 透传的关系:http.NewRequestWithContext(ctx, ...) 已把请求级取消/deadline
// 透传到底层 transport;TracePropagator 补齐的是跨进程的 span 链路(traceparent)。
// 二者是"调用方上下文透传"的两个层面:缺前者则取消信号断,缺后者则 IdP 侧 trace 断链。
//
// OTel 桥接示例(宿主侧,不进 SDK go.mod):
//
//	type otelPropagator struct{ p propagation.TextMapPropagator }
//	func (o otelPropagator) Inject(ctx context.Context, c http.HeaderCarrier) {
//	    // SDK HeaderCarrier 与 OTel propagation.HeaderCarrier 同构;
//	    // 写一个转发 Set/Get 的薄 adapter 即可桥接。
//	    o.p.Inject(ctx, otelCarrier{c})
//	}
//
// Experimental:beta 阶段接入;Inject 单方法接口设计稳定,
// GA 前若需扩展(如 Extract、baggage)会在不破坏 Inject 的前提下追加方法。
type TracePropagator interface {
	Inject(ctx context.Context, carrier HeaderCarrier)
}
