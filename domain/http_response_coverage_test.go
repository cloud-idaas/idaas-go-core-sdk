package domain

import "testing"

// TestRequestId_NilReceiver 确保 nil receiver 不 panic，返回空串。
func TestRequestId_NilReceiver(t *testing.T) {
	var r *HttpResponse
	if got := r.RequestId(); got != "" {
		t.Errorf("nil receiver RequestId() = %q, want empty", got)
	}
}

// TestRequestId_FromHeader 头部命中。
func TestRequestId_FromHeader(t *testing.T) {
	r := &HttpResponse{
		StatusCode: 200,
		Headers: map[string][]string{
			"X-Request-Id": {"req-abc-123"},
		},
		Body: []byte(`{}`),
	}
	if got := r.RequestId(); got != "req-abc-123" {
		t.Errorf("RequestId() = %q, want %q", got, "req-abc-123")
	}
}

// TestRequestId_FromHeaderAlt 变体头部命中。
func TestRequestId_FromHeaderAlt(t *testing.T) {
	r := &HttpResponse{
		Headers: map[string][]string{
			"X-Ca-Request-Id": {"alt-req-456"},
		},
	}
	if got := r.RequestId(); got != "alt-req-456" {
		t.Errorf("RequestId() = %q, want %q", got, "alt-req-456")
	}
}

// TestRequestId_FromBody 无头部时从 body 提取。
func TestRequestId_FromBody(t *testing.T) {
	r := &HttpResponse{
		Headers: map[string][]string{},
		Body:    []byte(`{"request_id":"body-abc"}`),
	}
	if got := r.RequestId(); got != "body-abc" {
		t.Errorf("RequestId() = %q, want %q", got, "body-abc")
	}
}

// TestRequestId_FromBodyCamel camelCase 字段。
func TestRequestId_FromBodyCamel(t *testing.T) {
	r := &HttpResponse{
		Headers: map[string][]string{},
		Body:    []byte(`{"requestId":"body-camel"}`),
	}
	if got := r.RequestId(); got != "body-camel" {
		t.Errorf("RequestId() = %q, want %q", got, "body-camel")
	}
}

// TestRequestId_HeaderPriority 头部优先于 body。
func TestRequestId_HeaderPriority(t *testing.T) {
	r := &HttpResponse{
		Headers: map[string][]string{
			"X-Request-Id": {"from-header"},
		},
		Body: []byte(`{"request_id":"from-body"}`),
	}
	if got := r.RequestId(); got != "from-header" {
		t.Errorf("RequestId() = %q, want %q (header should take priority)", got, "from-header")
	}
}

// TestRequestId_NothingFound 头部和 body 都没有 requestId 时返回空串。
func TestRequestId_NothingFound(t *testing.T) {
	r := &HttpResponse{
		Headers: map[string][]string{"Content-Type": {"application/json"}},
		Body:    []byte(`{"error":"invalid"}`),
	}
	if got := r.RequestId(); got != "" {
		t.Errorf("RequestId() = %q, want empty", got)
	}
}

// TestRequestId_EmptyEverything 所有字段为空。
func TestRequestId_EmptyEverything(t *testing.T) {
	r := &HttpResponse{}
	if got := r.RequestId(); got != "" {
		t.Errorf("RequestId() = %q, want empty", got)
	}
}

// ---------- headerRequestId ----------

// TestHeaderRequestId_CaseInsensitive 大小写不敏感。
func TestHeaderRequestId_CaseInsensitive(t *testing.T) {
	tests := []struct {
		name   string
		header string
		value  string
	}{
		{"lowercase", "x-request-id", "lower-1"},
		{"uppercase", "X-REQUEST-ID", "upper-2"},
		{"mixed", "X-Request-ID", "mixed-3"},
		{"alt lowercase", "x-ca-request-id", "alt-lower-4"},
		{"alt mixed", "X-Ca-Request-Id", "alt-mixed-5"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &HttpResponse{
				Headers: map[string][]string{
					tt.header: {tt.value},
				},
			}
			if got := r.headerRequestId(); got != tt.value {
				t.Errorf("headerRequestId() = %q, want %q", got, tt.value)
			}
		})
	}
}

// TestHeaderRequestId_FirstNonEmptyInList 多个值时取第一个非空。
func TestHeaderRequestId_FirstNonEmptyInList(t *testing.T) {
	r := &HttpResponse{
		Headers: map[string][]string{
			"X-Request-Id": {"", "second-val", "third-val"},
		},
	}
	if got := r.headerRequestId(); got != "second-val" {
		t.Errorf("headerRequestId() = %q, want %q", got, "second-val")
	}
}

// TestHeaderRequestId_AllEmptyVals 所有值都为空 → 继续查其他键。
func TestHeaderRequestId_AllEmptyVals(t *testing.T) {
	r := &HttpResponse{
		Headers: map[string][]string{
			"X-Request-Id":    {"", ""},
			"X-Ca-Request-Id": {"fallback"},
			"Content-Type":    {"application/json"},
		},
	}
	if got := r.headerRequestId(); got != "fallback" {
		t.Errorf("headerRequestId() = %q, want %q", got, "fallback")
	}
}

// TestHeaderRequestId_NoMatchingHeader 无匹配键。
func TestHeaderRequestId_NoMatchingHeader(t *testing.T) {
	r := &HttpResponse{
		Headers: map[string][]string{
			"Content-Type": {"application/json"},
		},
	}
	if got := r.headerRequestId(); got != "" {
		t.Errorf("headerRequestId() = %q, want empty", got)
	}
}

// TestHeaderRequestId_EmptyHeaders 空头部 map。
func TestHeaderRequestId_EmptyHeaders(t *testing.T) {
	r := &HttpResponse{Headers: map[string][]string{}}
	if got := r.headerRequestId(); got != "" {
		t.Errorf("headerRequestId() = %q, want empty", got)
	}
}

// TestHeaderRequestId_NilHeaders nil headers map。
func TestHeaderRequestId_NilHeaders(t *testing.T) {
	r := &HttpResponse{}
	if got := r.headerRequestId(); got != "" {
		t.Errorf("headerRequestId() = %q, want empty", got)
	}
}

// ---------- bodyRequestId ----------

// TestBodyRequestId_SnakeCase snake_case。
func TestBodyRequestId_SnakeCase(t *testing.T) {
	r := &HttpResponse{Body: []byte(`{"request_id":"snake-val"}`)}
	if got := r.bodyRequestId(); got != "snake-val" {
		t.Errorf("bodyRequestId() = %q, want %q", got, "snake-val")
	}
}

// TestBodyRequestId_CamelCase camelCase。
func TestBodyRequestId_CamelCase(t *testing.T) {
	r := &HttpResponse{Body: []byte(`{"requestId":"camel-val"}`)}
	if got := r.bodyRequestId(); got != "camel-val" {
		t.Errorf("bodyRequestId() = %q, want %q", got, "camel-val")
	}
}

// TestBodyRequestId_SnakeTakesPriority 两个字段都有时 snake_case 优先。
func TestBodyRequestId_SnakeTakesPriority(t *testing.T) {
	r := &HttpResponse{Body: []byte(`{"request_id":"snake","requestId":"camel"}`)}
	if got := r.bodyRequestId(); got != "snake" {
		t.Errorf("bodyRequestId() = %q, want %q (snake_case takes priority)", got, "snake")
	}
}

// TestBodyRequestId_NoMatchingField body 里没有 requestId 字段。
func TestBodyRequestId_NoMatchingField(t *testing.T) {
	r := &HttpResponse{Body: []byte(`{"error":"invalid","message":"bad request"}`)}
	if got := r.bodyRequestId(); got != "" {
		t.Errorf("bodyRequestId() = %q, want empty", got)
	}
}

// TestBodyRequestId_EmptyBody 空 body。
func TestBodyBodyRequestId_EmptyBody(t *testing.T) {
	r := &HttpResponse{Body: nil}
	if got := r.bodyRequestId(); got != "" {
		t.Errorf("bodyRequestId() = %q, want empty", got)
	}
}

// TestBodyRequestId_WhitespaceOnly 只有空白。
func TestBodyRequestId_WhitespaceOnly(t *testing.T) {
	r := &HttpResponse{Body: []byte("   \n  ")}
	if got := r.bodyRequestId(); got != "" {
		t.Errorf("bodyRequestId() = %q, want empty", got)
	}
}

// TestBodyRequestId_NonJSON 非 JSON body。
func TestBodyRequestId_NonJSON(t *testing.T) {
	r := &HttpResponse{Body: []byte("<html>not json</html>")}
	if got := r.bodyRequestId(); got != "" {
		t.Errorf("bodyRequestId() = %q, want empty", got)
	}
}

// TestBodyRequestId_ArrayNotObject JSON 数组不是对象。
func TestBodyRequestId_ArrayNotObject(t *testing.T) {
	r := &HttpResponse{Body: []byte(`[1,2,3]`)}
	if got := r.bodyRequestId(); got != "" {
		t.Errorf("bodyRequestId() = %q, want empty", got)
	}
}

// TestBodyRequestId_InvalidJSON 起始字符是 { 但内容不是合法 JSON。
func TestBodyRequestId_InvalidJSON(t *testing.T) {
	r := &HttpResponse{Body: []byte(`{this is not json}`)}
	if got := r.bodyRequestId(); got != "" {
		t.Errorf("bodyRequestId() = %q, want empty", got)
	}
}

// TestBodyRequestId_WithWhitespace 前后空白的合法 JSON。
func TestBodyRequestId_WithWhitespace(t *testing.T) {
	r := &HttpResponse{Body: []byte(`  {"request_id":"padded"}  `)}
	if got := r.bodyRequestId(); got != "padded" {
		t.Errorf("bodyRequestId() = %q, want %q", got, "padded")
	}
}

// TestBodyRequestId_BothEmpty 两个字段都为空串。
func TestBodyRequestId_BothEmpty(t *testing.T) {
	r := &HttpResponse{Body: []byte(`{"request_id":"","requestId":""}`)}
	if got := r.bodyRequestId(); got != "" {
		t.Errorf("bodyRequestId() = %q, want empty", got)
	}
}

// TestBodyRequestId_LargeBody 超过 maxRequestIdProbeBody 的 body 被跳过。
func TestBodyRequestId_LargeBody(t *testing.T) {
	// 构造一个超过 64KB 的 body，以 { 开头
	oversized := make([]byte, maxRequestIdProbeBody+100)
	for i := range oversized {
		oversized[i] = 'x'
	}
	oversized[0] = '{'
	r := &HttpResponse{Body: oversized}
	if got := r.bodyRequestId(); got != "" {
		t.Errorf("bodyRequestId() on oversized body = %q, want empty", got)
	}
}

// ---------- firstNonEmpty ----------

// TestFirstNonEmpty 各种输入。
func TestFirstNonEmpty(t *testing.T) {
	tests := []struct {
		name   string
		values []string
		want   string
	}{
		{"nil slice", nil, ""},
		{"empty slice", []string{}, ""},
		{"single non-empty", []string{"only"}, "only"},
		{"single empty", []string{""}, ""},
		{"first non-empty", []string{"a", "b", "c"}, "a"},
		{"leading empties", []string{"", "", "third"}, "third"},
		{"all empty", []string{"", "", ""}, ""},
		{"middle non-empty", []string{"", "mid", ""}, "mid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := firstNonEmpty(tt.values); got != tt.want {
				t.Errorf("firstNonEmpty(%v) = %q, want %q", tt.values, got, tt.want)
			}
		})
	}
}
