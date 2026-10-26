package domain

// DeviceCodeResponse Device Code 响应结构体
type DeviceCodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int64  `json:"expires_in"`
	ExpiresAt               int64  `json:"expires_at,omitempty"`
	Interval                int64  `json:"interval"`
}
