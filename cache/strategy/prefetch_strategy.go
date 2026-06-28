package strategy

// PrefetchStrategy 预取策略接口 (§7.5)
type PrefetchStrategy interface {
	// Start 启动预取
	Start()

	// Stop 停止预取
	Stop()

	// Close 关闭资源
	Close()
}
