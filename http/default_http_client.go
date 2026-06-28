package http

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/aliyun/idaas-go-core-sdk/constants"
	"github.com/aliyun/idaas-go-core-sdk/domain"
	"github.com/aliyun/idaas-go-core-sdk/enums"
	"github.com/aliyun/idaas-go-core-sdk/errors"
)

// DefaultHttpClient 默认 HTTP 客户端实现 (§9.4)
type DefaultHttpClient struct {
	client *http.Client
}

// 默认超时（毫秒）。当调用方未显式配置时使用。
const (
	defaultConnectTimeoutMs = 30000 // 连接 30 秒
	defaultReadTimeoutMs    = 60000 // 读取 60 秒
)

// NewDefaultHttpClient 创建 DefaultHttpClient（使用默认超时、启用证书校验）。
//
// connectTimeoutMs / readTimeoutMs 单位为**毫秒**，与 config.HttpConfiguration 的字段
// 注释保持一致。传入 <=0 时回退到默认值。
//
// 关键配置：
//   - connectTimeout 控制 TCP Dial 阶段超时，避免 DNS/连通性故障下整体卡住
//   - readTimeout 同时作为 http.Client.Timeout 与 ResponseHeaderTimeout
//   - 强制 TLS 最低版本 1.2（与阿里云安全规范一致）
//   - 复用连接池（MaxIdleConns / MaxIdleConnsPerHost），高并发下避免重复 TLS 握手
//   - 显式 TLSHandshakeTimeout 防止被慢握手挂死
func NewDefaultHttpClient(connectTimeoutMs, readTimeoutMs int) *DefaultHttpClient {
	return NewDefaultHttpClientWithOptions(connectTimeoutMs, readTimeoutMs, false)
}

// NewDefaultHttpClientWithOptions 创建 DefaultHttpClient，支持自定义超时（毫秒）与是否跳过 TLS 证书校验。
//
// insecureSkipVerify 仅应在测试 / 自签名证书的内网联调场景使用，生产环境务必保持 false，
// 否则会丧失对中间人攻击的防护。
func NewDefaultHttpClientWithOptions(connectTimeoutMs, readTimeoutMs int, insecureSkipVerify bool) *DefaultHttpClient {
	if connectTimeoutMs <= 0 {
		connectTimeoutMs = defaultConnectTimeoutMs
	}
	if readTimeoutMs <= 0 {
		readTimeoutMs = defaultReadTimeoutMs
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
			Timeout:   readTimeout,
			Transport: transport,
		},
	}
}

// Execute 执行 HTTP 请求 (§9.4)
func (c *DefaultHttpClient) Execute(request *domain.HttpRequest) (*domain.HttpResponse, error) {
	var req *http.Request
	var err error

	// 构建 URL
	fullURL := request.URL
	if len(request.QueryParams) > 0 {
		u, err := url.Parse(request.URL)
		if err != nil {
			return nil, errors.NewHttpError("InvalidURL", "Failed to parse request URL: "+err.Error(), 0, err)
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

	// 构建请求体
	var bodyReader io.Reader
	if request.Body != nil {
		switch request.ContentType {
		case enums.ContentTypeForm:
			if formData, ok := request.Body.(url.Values); ok {
				encodedBody := formData.Encode()
				bodyReader = bytes.NewBufferString(encodedBody)
			} else if strBody, ok := request.Body.(string); ok {
				bodyReader = bytes.NewBufferString(strBody)
			}
		case enums.ContentTypeJson:
			jsonData, err := json.Marshal(request.Body)
			if err != nil {
				return nil, errors.NewEncodingError("EncodingError", "Failed to marshal JSON body", err)
			}
			bodyReader = bytes.NewBuffer(jsonData)
		default:
			if strBody, ok := request.Body.(string); ok {
				bodyReader = bytes.NewBufferString(strBody)
			}
		}
	}

	// 创建 HTTP 请求
	req, err = http.NewRequest(string(request.Method), fullURL, bodyReader)
	if err != nil {
		return nil, errors.NewHttpError("ClientError", "Failed to create HTTP request", 0, err)
	}

	// 设置 Headers
	for k, v := range request.Headers {
		req.Header.Set(k, v)
	}

	// 设置 Content-Type
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

	// 执行请求
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, errors.NewHttpError("ConnectTimeOut", "HTTP request failed", 0, err)
	}
	defer resp.Body.Close()

	// 读取响应体
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.NewHttpError("ReadTimeOut", "Failed to read response body", resp.StatusCode, err)
	}

	// 构建响应
	httpResp := &domain.HttpResponse{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       body,
	}

	return httpResp, nil
}

// Get 执行 GET 请求
func (c *DefaultHttpClient) Get(url string, headers map[string]string) (*domain.HttpResponse, error) {
	request := &domain.HttpRequest{
		Method:  enums.HttpMethodGet,
		URL:     url,
		Headers: headers,
	}
	return c.Execute(request)
}

// Post 执行 POST 请求
func (c *DefaultHttpClient) Post(url string, headers map[string]string, body interface{}) (*domain.HttpResponse, error) {
	request := &domain.HttpRequest{
		Method:      enums.HttpMethodPost,
		URL:         url,
		Headers:     headers,
		Body:        body,
		ContentType: enums.ContentTypeJson,
	}
	return c.Execute(request)
}
