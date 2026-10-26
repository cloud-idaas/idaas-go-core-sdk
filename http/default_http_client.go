package http

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/cloud-idaas/idaas-go-core-sdk/constants"
	"github.com/cloud-idaas/idaas-go-core-sdk/domain"
	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
	"github.com/cloud-idaas/idaas-go-core-sdk/errors"
)

type DefaultHttpClient struct {
	client *http.Client
	// propagator 注入分布式 trace context(W3C TraceContext / B3)。
	// nil 表示不注入(beta 默认,零回归);非 nil 时 ExecuteContext 在发起请求前
	// 把 ctx 中的 trace 上下文写入请求头,使出站请求关联到宿主 trace。
	propagator TracePropagator
}

// maxResponseBodySize 是单次响应体读取的硬上限。
// 4 MiB 既给大错误页/JWKS 留足余量，又能在恶意/故障服务返回超大响应时保护进程内存。
const maxResponseBodySize = 4 << 20 // 4 MiB

const maxRedirects = 5

// secureCheckRedirect 防止重定向导致凭证外泄：跨 host 或 scheme 降级
// （https→http 同 host）时剥离 Authorization/Cookie 头；当 307/308 保留
// 请求体时还需丢弃 body（client_secret_post 的 secret 在请求体里），
// 防止凭证被重放到不安全的目标。token endpoint 实际不会 3xx，此为纵深防御。
func secureCheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return fmt.Errorf("stopped after %d redirects", maxRedirects)
	}
	if len(via) > 0 {
		prev := via[len(via)-1]
		// sameSecureHost: 同 host 且 scheme 未降级（https→http 视为降级）。
		sameSecureHost := req.URL.Host == prev.URL.Host && !isSchemeDowngrade(prev.URL.Scheme, req.URL.Scheme)
		if !sameSecureHost {
			req.Header.Del(constants.HeaderAuthorization)
			req.Header.Del(constants.HeaderCookie)
			// IMDS 元数据 token 在跨 host 重定向时同样必须剥离。
			// token endpoint 不会 3xx,但 PKCS7/OIDC deploy-env 流程先经 IMDS 取 attested document,
			// 再向 token endpoint 发 assertion——若 IMDS host 3xx 到外部,metadata token 会泄漏。
			req.Header.Del(constants.HeaderXAliyunEcsMetadataToken)
			req.Header.Del(constants.HeaderXAwsEc2MetadataToken)
			req.Header.Del(constants.HeaderXAwsEc2MetadataTokenTtlSeconds)
			req.Header.Del(constants.HeaderMetadata)
			req.Header.Del(constants.HeaderMetadataFlavor)
			// 307/308 保留 method 和 body；此时剥离 body 以防止凭证
			// （oauth2 form 中的 client_secret）被重放到不安全目标。
			// 301/302/303 已由 net/http 将方法改为 GET 并丢弃 body。
			if req.Method == prev.Method && isBodyBearingMethod(req.Method) {
				req.Body = http.NoBody
				req.ContentLength = 0
				req.Header.Del(constants.HeaderContentType)
				req.Header.Del("Content-Length")
				// GetBody 用于重定向时重新读取请求体；跨 host/降级时一并清空，
				// 避免下游 Transport 试图再次构造 body。
				req.GetBody = nil
			}
		}
	}
	return nil
}

// isSchemeDowngrade 判断重定向前后 scheme 是否构成安全降级。
// 唯一需要警惕的降级：prev https → new http（同 host 下 TLS 被剥离）。
// http→https 是升级，http→http / https→https 无变化，均非降级。
func isSchemeDowngrade(prevScheme, newScheme string) bool {
	return strings.EqualFold(prevScheme, "https") && strings.EqualFold(newScheme, "http")
}

// isBodyBearingMethod 判断 HTTP method 是否通常携带请求体。
// 仅 POST/PUT/PATCH 在 307/308 重定向时需要额外剥离 body。
func isBodyBearingMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		return true
	default:
		return false
	}
}

// NewDefaultHttpClient 创建 DefaultHttpClient（使用默认超时、启用证书校验）。
// connectTimeoutMs / readTimeoutMs 单位为毫秒，<=0 时回退到默认值。
func NewDefaultHttpClient(connectTimeoutMs, readTimeoutMs int) *DefaultHttpClient {
	return NewDefaultHttpClientWithOptions(connectTimeoutMs, readTimeoutMs, false)
}

// NewDefaultHttpClientWithOptions 创建 DefaultHttpClient，支持自定义超时（毫秒）与是否跳过 TLS 证书校验。
// insecureSkipVerify 仅应在测试/自签名证书的内网联调场景使用，生产环境务必保持 false。
func NewDefaultHttpClientWithOptions(connectTimeoutMs, readTimeoutMs int, insecureSkipVerify bool) *DefaultHttpClient {
	if connectTimeoutMs <= 0 {
		connectTimeoutMs = constants.DefaultConnectTimeoutMs
	}
	if readTimeoutMs <= 0 {
		readTimeoutMs = constants.DefaultReadTimeoutMs
	}

	connectTimeout := time.Duration(connectTimeoutMs) * time.Millisecond
	readTimeout := time.Duration(readTimeoutMs) * time.Millisecond

	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   connectTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: readTimeout,
		ExpectContinueTimeout: 1 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		DisableKeepAlives:     false,
		ForceAttemptHTTP2:     true,
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: insecureSkipVerify,
		},
	}
	return &DefaultHttpClient{
		client: &http.Client{
			Timeout:       readTimeout,
			Transport:     transport,
			CheckRedirect: secureCheckRedirect,
		},
	}
}

// WithTracePropagator 注入分布式 trace context 透传器(W3C TraceContext / B3)。
// 注入后,ExecuteContext 在发起请求前把 ctx 中的 trace 上下文写入请求头(traceparent 等),
// 使 SDK 向 token endpoint / IMDS / OIDC provider 的出站请求能关联到宿主的分布式 trace,
// 避免凭证获取这一跳在 IdP 侧断链。
//
// nil 等同于不调用(beta 默认不注入,零回归)。SDK 不内置 OTel 依赖,实现方负责按
// 约定写头;OTel 桥接见 TracePropagator 文档。
//
// Experimental:beta 阶段接入;GA 前若 propagator 接口扩展会保持
// Inject 向后兼容。
func (c *DefaultHttpClient) WithTracePropagator(p TracePropagator) *DefaultHttpClient {
	if p != nil {
		c.propagator = p
	}
	return c
}

// Execute 执行 HTTP 请求，等价于 ExecuteContext(context.Background(), request)。
func (c *DefaultHttpClient) Execute(request *domain.HttpRequest) (*domain.HttpResponse, error) {
	return c.ExecuteContext(context.Background(), request)
}

// ExecuteContext 执行带 context 的 HTTP 请求，ctx 取消/deadline 能中断进行中的网络 IO。
func (c *DefaultHttpClient) ExecuteContext(ctx context.Context, request *domain.HttpRequest) (*domain.HttpResponse, error) {
	var req *http.Request
	var err error

	fullURL := request.URL
	if len(request.QueryParams) > 0 {
		u, err := url.Parse(request.URL)
		if err != nil {
			return nil, errors.NewHttpError(constants.InvalidURL, "Failed to parse request URL: "+err.Error(), 0, err)
		}
		q := u.Query()
		for k, v := range request.QueryParams {
			for _, val := range v {
				q.Add(k, val)
			}
		}
		u.RawQuery = q.Encode()
		fullURL = u.String()
	}

	var bodyReader io.Reader
	if request.Body != nil {
		switch request.ContentType {
		case enums.ContentTypeForm:
			switch body := request.Body.(type) {
			case url.Values:
				bodyReader = bytes.NewBufferString(body.Encode())
			case string:
				bodyReader = bytes.NewBufferString(body)
			}
		case enums.ContentTypeJson:
			jsonData, err := json.Marshal(request.Body)
			if err != nil {
				return nil, errors.NewEncodingError(constants.EncodeFailed, "Failed to marshal JSON body", err)
			}
			bodyReader = bytes.NewBuffer(jsonData)
		default:
			if strBody, ok := request.Body.(string); ok {
				bodyReader = bytes.NewBufferString(strBody)
			}
		}
	}

	req, err = http.NewRequestWithContext(ctx, string(request.Method), fullURL, bodyReader)
	if err != nil {
		return nil, errors.NewHttpError(constants.ClientError, "Failed to create HTTP request", 0, err)
	}

	// 先注入 SDK User-Agent，再应用调用方 Headers，使调用方可显式覆盖 UA。
	req.Header.Set(constants.HeaderUserAgent, BuildUserAgent())

	for k, v := range request.Headers {
		req.Header.Set(k, v)
	}

	if request.ContentType != "" {
		switch request.ContentType {
		case enums.ContentTypeForm:
			req.Header.Set(constants.HeaderContentType, constants.ContentTypeFormUrlEncoded)
		case enums.ContentTypeJson:
			req.Header.Set(constants.HeaderContentType, constants.ContentTypeJson)
		case enums.ContentTypeXml:
			req.Header.Set(constants.HeaderContentType, constants.ContentTypeXml)
		}
	}

	// 注入分布式 trace context(若宿主配置):把 ctx 中的 traceparent/tracestate 等
	// 写入请求头,使出站请求关联到宿主 trace。beta 默认不注入(propagator==nil)。
	// 放在所有 header 设置之后、Do 之前,确保 propagator 看到最终请求头。
	if c.propagator != nil {
		c.propagator.Inject(ctx, req.Header)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, classifyHttpError(err)
	}
	defer resp.Body.Close()

	// LimitReader 封顶防超大响应拖垮内存；多读 1 字节判断是否被截断，超限直接返回错误不返回部分体。
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize+1))
	if err != nil {
		return nil, classifyReadBodyError(err, resp.StatusCode)
	}
	if int64(len(body)) > maxResponseBodySize {
		return nil, errors.NewHttpError(
			constants.ResponseTooLarge,
			fmt.Sprintf("response body exceeds %d-byte limit (got %d bytes)", maxResponseBodySize, len(body)),
			resp.StatusCode,
			nil,
		)
	}

	httpResp := &domain.HttpResponse{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       body,
	}

	return httpResp, nil
}

func (c *DefaultHttpClient) Get(rawURL string, headers map[string]string) (*domain.HttpResponse, error) {
	request := &domain.HttpRequest{
		Method:  enums.HttpMethodGet,
		URL:     rawURL,
		Headers: headers,
	}
	return c.Execute(request)
}

func (c *DefaultHttpClient) Post(rawURL string, headers map[string]string, body interface{}) (*domain.HttpResponse, error) {
	request := &domain.HttpRequest{
		Method:      enums.HttpMethodPost,
		URL:         rawURL,
		Headers:     headers,
		Body:        body,
		ContentType: enums.ContentTypeJson,
	}
	return c.Execute(request)
}

// CloseIdleConnections 释放底层 Transport 持有的空闲 TCP 连接，
// 供 factory Reset 调用避免泄漏；调用后 client 仍可用，新连接按需建立。
func (c *DefaultHttpClient) CloseIdleConnections() {
	c.client.CloseIdleConnections()
}

// classifyHttpError 把 client.Do 返回的错误按根因归类为具体错误码。
// 原实现一律标为 ConnectTimeOut，DNS/TLS/RST/EOF 全被误标，导致排查方向错误
// （TLS 证书错误重试无意义、DNS 故障应查网络而非超时）。
// 分类优先级（从最具体到最通用）：context 取消 → TLS（x509 证书校验 / tls.RecordHeader）→ DNS → RST → 超时 → 兜底。
// Go 1.18 约束：tls.CertificateVerificationError (1.20) 不可用，退回 x509 错误类型断言。
func classifyHttpError(err error) error {
	if stderrors.Is(err, context.Canceled) {
		return errors.NewHttpError(constants.ClientError, "request cancelled by context", 0, err)
	}
	if stderrors.Is(err, context.DeadlineExceeded) {
		return errors.NewHttpError(constants.ConnectTimeOut, "request deadline exceeded", 0, err)
	}

	// x509 三个错误类型 Error() 用值接收器，实际返回值类型，stderrors.As 目标也须用值类型。
	var unknownAuthErr x509.UnknownAuthorityError
	var certInvalidErr x509.CertificateInvalidError
	var hostnameErr x509.HostnameError
	if stderrors.As(err, &unknownAuthErr) || stderrors.As(err, &certInvalidErr) || stderrors.As(err, &hostnameErr) {
		return errors.NewHttpError(constants.TlsHandshakeFailed, "TLS certificate verification failed: "+err.Error(), 0, err)
	}

	// tls.RecordHeaderError：目标端点返回了非 TLS 数据（如 HTTPS 端口实际服务 HTTP），
	// 导致 TLS 握手在读取 record header 阶段失败。归为 TlsHandshakeFailed 而非兜底 ClientError。
	var recordHeaderErr tls.RecordHeaderError
	if stderrors.As(err, &recordHeaderErr) {
		return errors.NewHttpError(constants.TlsHandshakeFailed, "TLS handshake failed: "+err.Error(), 0, err)
	}

	var opErr *net.OpError
	if stderrors.As(err, &opErr) {
		if opErr.Op == "dial" {
			var dnsErr *net.DNSError
			if stderrors.As(err, &dnsErr) {
				return errors.NewHttpError(constants.DnsLookupFailed, "DNS resolution failed: "+err.Error(), 0, err)
			}
			if isConnectionReset(opErr.Err) {
				return errors.NewHttpError(constants.ConnectionReset, "connection reset by peer", 0, err)
			}
		}
		var netErr net.Error
		if stderrors.As(err, &netErr) && netErr.Timeout() {
			return errors.NewHttpError(constants.ConnectTimeOut, "connection timed out", 0, err)
		}
	}

	var netErr net.Error
	if stderrors.As(err, &netErr) && netErr.Timeout() {
		return errors.NewHttpError(constants.ConnectTimeOut, "network operation timed out", 0, err)
	}

	return errors.NewHttpError(constants.ClientError, "HTTP request failed: "+err.Error(), 0, err)
}

// classifyReadBodyError 对 io.ReadAll 返回的错误做精确分类。
// context.Canceled 是调用方主动取消，映射为 ClientError 而非 ReadTimeOut，避免误导重试。
func classifyReadBodyError(err error, statusCode int) error {
	if stderrors.Is(err, context.Canceled) {
		return errors.NewHttpError(constants.ClientError, "read cancelled by context", statusCode, err)
	}
	if stderrors.Is(err, context.DeadlineExceeded) {
		return errors.NewHttpError(constants.ReadTimeOut, "read deadline exceeded", statusCode, err)
	}
	if stderrors.Is(err, io.ErrUnexpectedEOF) || stderrors.Is(err, io.EOF) {
		return errors.NewHttpError(constants.ResponseTruncated, "response body truncated: "+err.Error(), statusCode, err)
	}
	if isConnectionReset(err) {
		return errors.NewHttpError(constants.ConnectionReset, "connection reset while reading response", statusCode, err)
	}
	var netErr net.Error
	if stderrors.As(err, &netErr) && netErr.Timeout() {
		return errors.NewHttpError(constants.ReadTimeOut, "read timed out", statusCode, err)
	}
	// 兜底归为 ClientError，避免未知读错误被误标为超时导致误导重试。
	return errors.NewHttpError(constants.ClientError, "failed to read response body: "+err.Error(), statusCode, err)
}

// isConnectionReset 精确匹配 ECONNRESET/EPIPE 而非任意 syscall.Errno。
// 原实现用 errors.As(*syscall.Errno) 会匹配 ETIMEDOUT/ECONNREFUSED 等，
// 导致读取超时被误分类为 ConnectionReset (F-01 修复)。
func isConnectionReset(err error) bool {
	if err == nil {
		return false
	}
	if stderrors.Is(err, syscall.ECONNRESET) || stderrors.Is(err, syscall.EPIPE) {
		return true
	}
	// 字符串兜底：不同平台/Go 版本的包装层可能未暴露结构化类型。
	msg := err.Error()
	return strings.Contains(msg, "connection reset by peer") || strings.Contains(msg, "broken pipe")
}
