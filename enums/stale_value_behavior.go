package enums

// StaleValueBehavior 枚举
type StaleValueBehavior string

const (
	StaleValueBehaviorBlock   StaleValueBehavior = "BLOCK"
	StaleValueBehaviorAllow   StaleValueBehavior = "ALLOW"
	StaleValueBehaviorRefresh StaleValueBehavior = "REFRESH"
)
