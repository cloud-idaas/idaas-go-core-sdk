package strategy

// PrefetchStrategy 预取策略接口。
//
// 对齐 Java/Python 的 prefetch(Runnable) 模式：
// - Prefetch: 接受一个 refresh 闭包，由策略决定如何调度执行
// - Close: 释放策略持有的后台资源
type PrefetchStrategy interface {
	// Prefetch 执行一次预取刷新。
	// 由调用方在检测到 token 即将过期时触发；
	// 策略实现决定是同步执行还是异步、是否限流。
	Prefetch(refresh func())

	// Close 释放后台 goroutine / ticker 等资源。
	Close() error
}
