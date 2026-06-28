package enums

// StaleValueBehavior 枚举 (§3.6.2)
type StaleValueBehavior string

const (
	StaleValueBehaviorBlock   StaleValueBehavior = "BLOCK"
	StaleValueBehaviorAllow   StaleValueBehavior = "ALLOW"
	StaleValueBehaviorRefresh StaleValueBehavior = "REFRESH"
)
