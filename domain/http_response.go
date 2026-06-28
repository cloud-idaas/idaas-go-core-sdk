package domain

// HttpResponse HTTP 响应模型 (§9.4)
type HttpResponse struct {
	StatusCode int
	Headers    map[string][]string
	Body       []byte
}

// IsSuccess 判断响应是否成功 (§9.4)
func (r *HttpResponse) IsSuccess() bool {
	return r.StatusCode >= 200 && r.StatusCode < 300
}
