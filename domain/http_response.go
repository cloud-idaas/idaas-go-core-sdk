package domain

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/cloud-idaas/idaas-go-core-sdk/constants"
)

// HttpResponse HTTP 响应模型
type HttpResponse struct {
	StatusCode int
	Headers    map[string][]string
	Body       []byte
}

// IsSuccess 判断响应是否成功
func (r *HttpResponse) IsSuccess() bool {
	return r.StatusCode >= 200 && r.StatusCode < 300
}

// maxRequestIdProbeBody 在响应体里找 requestId 时愿意解析的最大字节数。
//
// requestId 只存在于错误响应/令牌响应这类小 JSON 里。设上限是为了避免
// 某个接口返回了 MB 级 body 时，SDK 为了一个排障字段去做一次全量 JSON 解析。
const maxRequestIdProbeBody = 64 * 1024

// RequestId 提取服务端请求 ID。
//
// 查找顺序：
// 1. 响应头 X-Request-Id / X-Ca-Request-Id；
// 2. 响应体 JSON 的 request_id / requestId。
//
// 之所以两处都看：Java SDK 是从**响应体**取的
// （DefaultOKHttpClientImp 里 `map.containsKey("request_id") ? ... : map.get("RequestId")`），
// 而 Go 侧设计约定走响应头。两种来源在服务端是并存的（老接口只给 body，
// 网关层统一加的是 header），只读一边必然在某类接口上拿不到值。
//
// 取不到时返回空串，**不返回 error**：requestId 是排障辅助信息，
// 绝不能因为它缺失或格式异常而让主流程失败。
func (r *HttpResponse) RequestId() string {
	if r == nil {
		return ""
	}
	if id := r.headerRequestId(); id != "" {
		return id
	}
	return r.bodyRequestId()
}

// headerRequestId 大小写不敏感地查响应头。
//
// net/http 会把 header key 规范化成 Canonical-Form，但 Headers 是一个裸 map，
// 也可能由 mock 或其它 HttpClient 实现填充，不能假定已规范化。
func (r *HttpResponse) headerRequestId() string {
	if len(r.Headers) == 0 {
		return ""
	}
	for _, want := range []string{constants.HeaderXRequestId, constants.HeaderXRequestIdAlt} {
		// 先走一次精确命中，常见情况下可省掉整表遍历
		if vs, ok := r.Headers[want]; ok {
			if v := firstNonEmpty(vs); v != "" {
				return v
			}
		}
		for k, vs := range r.Headers {
			if strings.EqualFold(k, want) {
				if v := firstNonEmpty(vs); v != "" {
					return v
				}
			}
		}
	}
	return ""
}

// bodyRequestId 从 JSON 响应体里取 requestId（与 Java SDK 对齐）。
func (r *HttpResponse) bodyRequestId() string {
	body := bytes.TrimSpace(r.Body)
	// 只处理 JSON 对象；非 JSON（HTML 错误页、空体）直接放弃，不浪费一次解析
	if len(body) == 0 || len(body) > maxRequestIdProbeBody || body[0] != '{' {
		return ""
	}
	// 两个字段而不是一个：Go 的 json 解码对 key 是大小写不敏感的，
	// 但 "request_id" 与 "requestId" 之间差了一个下划线，不是大小写差异，
	// 必须各给一个 tag 才能同时覆盖 Java 侧的 request_id 和 RequestId 两种写法。
	var probe struct {
		Snake string `json:"request_id"`
		Camel string `json:"requestId"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		// 解析失败是完全可以接受的：body 可能根本不是我们认识的结构。
		return ""
	}
	if probe.Snake != "" {
		return probe.Snake
	}
	return probe.Camel
}

func firstNonEmpty(values []string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
