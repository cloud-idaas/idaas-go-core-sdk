package domain

import (
	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
	"net/url"
)

// HttpRequest HTTP 请求模型
type HttpRequest struct {
	Method      enums.HttpMethod
	URL         string
	Headers     map[string]string
	QueryParams url.Values
	Body        interface{}
	ContentType enums.ContentType
}
