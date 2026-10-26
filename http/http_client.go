package http

import (
	"context"

	"github.com/cloud-idaas/idaas-go-core-sdk/domain"
)

// HttpClient HTTP 客户端接口
type HttpClient interface {
	// Execute 执行 HTTP 请求。
	//
	// 内部等价于 ExecuteContext(context.Background(), request)。
	// 优先使用 ExecuteContext 以支持请求级取消与 deadline。
	Execute(request *domain.HttpRequest) (*domain.HttpResponse, error)

	// ExecuteContext 执行带 context 的 HTTP 请求。
	//
	// ctx 用于请求级取消与整体 deadline 透传:在 gRPC / HTTP 服务端请求链路中,
	// 凭证获取不应脱离上层请求的生命周期。ctx 取消时,底层 http.Client.Do 会
	// 中断进行中的网络 IO 并返回 context.Canceled / DeadlineExceeded。
	ExecuteContext(ctx context.Context, request *domain.HttpRequest) (*domain.HttpResponse, error)

	// Get 执行 GET 请求
	Get(url string, headers map[string]string) (*domain.HttpResponse, error)

	// Post 执行 POST 请求
	Post(url string, headers map[string]string, body interface{}) (*domain.HttpResponse, error)
}

// ResourceCloser is an optional interface for HttpClient implementations that
// hold reusable resources (connection pools, idle TCP connections, goroutines).
// Implementations should call CloseIdleConnections to release pooled connections
// when the client is no longer needed (e.g. during factory Reset).
//
// This is a non-breaking extension: existing HttpClient implementations are not
// required to implement it; callers type-assert before invoking.
type ResourceCloser interface {
	CloseIdleConnections()
}
