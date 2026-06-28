package http

import (
	"github.com/aliyun/idaas-go-core-sdk/domain"
)

// HttpClient HTTP 客户端接口 (§9.4)
type HttpClient interface {
	// Execute 执行 HTTP 请求
	Execute(request *domain.HttpRequest) (*domain.HttpResponse, error)

	// Get 执行 GET 请求
	Get(url string, headers map[string]string) (*domain.HttpResponse, error)

	// Post 执行 POST 请求
	Post(url string, headers map[string]string, body interface{}) (*domain.HttpResponse, error)
}
