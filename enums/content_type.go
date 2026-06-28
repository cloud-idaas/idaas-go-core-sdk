package enums

// ContentType 枚举 (§13.6)
type ContentType string

const (
	ContentTypeForm ContentType = "FORM"
	ContentTypeJson ContentType = "JSON"
	ContentTypeXml  ContentType = "XML"
	ContentTypeRaw  ContentType = "RAW"
)
