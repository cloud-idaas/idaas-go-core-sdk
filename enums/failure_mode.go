package enums

// FailureMode 枚举。
//
// 控制刷新失败时的降级行为。beta 阶段仅解析,不启用;GA 阶段接入。
// 与 StaleValueBehavior 的关系:StaleValueBehavior 控制单次过期取值策略,
// FailureMode 控制连续失败时的整体降级开关(是否进入 DEGRADED 状态)。
type FailureMode string

const (
	// FailureModeFailFast 严格模式:刷新失败即返回错误,不返回陈旧值。
	// 适合安全敏感场景,宁可拒绝也不给过期凭证。
	FailureModeFailFast FailureMode = "FAIL_FAST"
	// FailureModeFailOpen 宽松模式:刷新失败时返回陈旧值(若有),
	// 优先保证可用性。与 StaleValueBehaviorRefresh 配合使用。
	FailureModeFailOpen FailureMode = "FAIL_OPEN"
	// FailureModeFailClosed 保守模式:刷新失败且无陈旧值时拒绝服务,
	// 有陈旧值时仍返回(与 FailOpen 的区别在于无陈旧值时的处理)。
	FailureModeFailClosed FailureMode = "FAIL_CLOSED"
)
