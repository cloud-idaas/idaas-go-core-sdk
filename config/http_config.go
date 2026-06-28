package config

// HttpConfiguration HTTP 配置结构体 (§13.4)
type HttpConfiguration struct {
	ConnectTimeout      int  `json:"connectTimeout,omitempty"` // 毫秒
	ReadTimeout         int  `json:"readTimeout,omitempty"`    // 毫秒
	UnsafeIgnoreSSLCert bool `json:"unsafeIgnoreSSLCert,omitempty"`
}
