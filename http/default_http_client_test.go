package http

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cloud-idaas/idaas-go-core-sdk/constants"
	"github.com/cloud-idaas/idaas-go-core-sdk/domain"
	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
	"github.com/cloud-idaas/idaas-go-core-sdk/errors"
)

// mockNetError implements net.Error for testing timeout/temporary behavior.
type mockNetError struct {
	msg       string
	timeout   bool
	temporary bool
}

func (e *mockNetError) Error() string   { return e.msg }
func (e *mockNetError) Timeout() bool   { return e.timeout }
func (e *mockNetError) Temporary() bool { return e.temporary }

func TestNewDefaultHttpClient(t *testing.T) {
	c := NewDefaultHttpClient(1000, 2000)
	if c == nil {
		t.Fatal("NewDefaultHttpClient returned nil")
	}
	if c.client == nil {
		t.Fatal("internal http.Client is nil")
	}

	// Verify it implements the HttpClient interface.
	var _ HttpClient = c

	// Verify timeout was set from readTimeoutMs.
	expectedTimeout := 2000 * time.Millisecond
	if c.client.Timeout != expectedTimeout {
		t.Errorf("client.Timeout = %v, want %v", c.client.Timeout, expectedTimeout)
	}

	// Verify transport is *http.Transport with expected fields.
	tr, ok := c.client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("Transport is not *http.Transport")
	}
	if tr.TLSClientConfig == nil {
		t.Fatal("TLSClientConfig is nil")
	}
	if tr.TLSClientConfig.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be false by default")
	}
	if tr.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %x, want %x", tr.TLSClientConfig.MinVersion, tls.VersionTLS12)
	}
	if tr.ResponseHeaderTimeout != expectedTimeout {
		t.Errorf("ResponseHeaderTimeout = %v, want %v", tr.ResponseHeaderTimeout, expectedTimeout)
	}
	if tr.MaxIdleConns != 100 {
		t.Errorf("MaxIdleConns = %d, want 100", tr.MaxIdleConns)
	}
	if tr.MaxIdleConnsPerHost != 10 {
		t.Errorf("MaxIdleConnsPerHost = %d, want 10", tr.MaxIdleConnsPerHost)
	}
	if tr.TLSHandshakeTimeout != 10*time.Second {
		t.Errorf("TLSHandshakeTimeout = %v, want 10s", tr.TLSHandshakeTimeout)
	}
}

func TestNewDefaultHttpClientWithOptions_DefaultFallback(t *testing.T) {
	tests := []struct {
		name           string
		connectTimeout int
		readTimeout    int
	}{
		{"zero", 0, 0},
		{"negative", -1, -1},
		{"large negative", -9999, -9999},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewDefaultHttpClient(tt.connectTimeout, tt.readTimeout)
			expectedRead := time.Duration(constants.DefaultReadTimeoutMs) * time.Millisecond
			if c.client.Timeout != expectedRead {
				t.Errorf("client.Timeout = %v, want %v (default)", c.client.Timeout, expectedRead)
			}
			tr := c.client.Transport.(*http.Transport)
			if tr.ResponseHeaderTimeout != expectedRead {
				t.Errorf("ResponseHeaderTimeout = %v, want %v (default)", tr.ResponseHeaderTimeout, expectedRead)
			}
		})
	}
}

func TestNewDefaultHttpClientWithOptions_WithDefaults(t *testing.T) {
	c := NewDefaultHttpClientWithOptions(0, 0, false)
	expectedRead := time.Duration(constants.DefaultReadTimeoutMs) * time.Millisecond
	if c.client.Timeout != expectedRead {
		t.Errorf("client.Timeout = %v, want %v", c.client.Timeout, expectedRead)
	}
}

func TestNewDefaultHttpClientWithOptions_CustomTimeouts(t *testing.T) {
	c := NewDefaultHttpClientWithOptions(3000, 7000, false)
	expectedRead := 7000 * time.Millisecond
	if c.client.Timeout != expectedRead {
		t.Errorf("client.Timeout = %v, want %v", c.client.Timeout, expectedRead)
	}
	tr := c.client.Transport.(*http.Transport)
	if tr.ResponseHeaderTimeout != expectedRead {
		t.Errorf("ResponseHeaderTimeout = %v, want %v", tr.ResponseHeaderTimeout, expectedRead)
	}
}

func TestNewDefaultHttpClientWithOptions_InsecureSkipVerify(t *testing.T) {
	t.Run("false", func(t *testing.T) {
		c := NewDefaultHttpClientWithOptions(1000, 1000, false)
		tr := c.client.Transport.(*http.Transport)
		if tr.TLSClientConfig.InsecureSkipVerify {
			t.Error("InsecureSkipVerify should be false")
		}
	})
	t.Run("true", func(t *testing.T) {
		c := NewDefaultHttpClientWithOptions(1000, 1000, true)
		tr := c.client.Transport.(*http.Transport)
		if !tr.TLSClientConfig.InsecureSkipVerify {
			t.Error("InsecureSkipVerify should be true")
		}
	})
}

func TestExecute_GET(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != string(enums.HttpMethodGet) {
			t.Errorf("method = %s, want %s", r.Method, enums.HttpMethodGet)
		}
		w.Header().Set("X-Custom-Resp", "yes")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello world"))
	}))
	defer server.Close()

	client := NewDefaultHttpClient(1000, 5000)
	resp, err := client.Execute(&domain.HttpRequest{
		Method: enums.HttpMethodGet,
		URL:    server.URL,
	})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if string(resp.Body) != "hello world" {
		t.Errorf("Body = %q, want %q", string(resp.Body), "hello world")
	}
	if vs, ok := resp.Headers["X-Custom-Resp"]; !ok || len(vs) == 0 || vs[0] != "yes" {
		t.Errorf("Header X-Custom-Resp = %v, want \"yes\"", resp.Headers["X-Custom-Resp"])
	}
}

func TestExecute_POST_JSON(t *testing.T) {
	var receivedBody []byte
	var receivedCT string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		receivedCT = r.Header.Get(constants.HeaderContentType)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(receivedBody)
	}))
	defer server.Close()

	client := NewDefaultHttpClient(1000, 5000)
	body := map[string]interface{}{"key": "value", "num": 42}
	resp, err := client.Execute(&domain.HttpRequest{
		Method:      enums.HttpMethodPost,
		URL:         server.URL,
		Body:        body,
		ContentType: enums.ContentTypeJson,
	})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusCreated)
	}
	if receivedCT != constants.ContentTypeJson {
		t.Errorf("Content-Type = %q, want %q", receivedCT, constants.ContentTypeJson)
	}
	// Verify server received valid JSON.
	var decoded map[string]interface{}
	if err := json.Unmarshal(receivedBody, &decoded); err != nil {
		t.Fatalf("server received invalid JSON: %v", err)
	}
	if decoded["key"] != "value" {
		t.Errorf("decoded[key] = %v, want %q", decoded["key"], "value")
	}
	if decoded["num"] != float64(42) {
		t.Errorf("decoded[num] = %v, want %d", decoded["num"], 42)
	}
}

func TestExecute_POST_Form(t *testing.T) {
	var receivedBody []byte
	var receivedCT string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		receivedCT = r.Header.Get(constants.HeaderContentType)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewDefaultHttpClient(1000, 5000)
	form := url.Values{}
	form.Set("key1", "value1")
	form.Set("key2", "value2")
	resp, err := client.Execute(&domain.HttpRequest{
		Method:      enums.HttpMethodPost,
		URL:         server.URL,
		Body:        form,
		ContentType: enums.ContentTypeForm,
	})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if receivedCT != constants.ContentTypeFormUrlEncoded {
		t.Errorf("Content-Type = %q, want %q", receivedCT, constants.ContentTypeFormUrlEncoded)
	}
	parsed, err := url.ParseQuery(string(receivedBody))
	if err != nil {
		t.Fatalf("failed to parse form body: %v", err)
	}
	if parsed.Get("key1") != "value1" || parsed.Get("key2") != "value2" {
		t.Errorf("form body = %q, expected key1=value1&key2=value2", string(receivedBody))
	}
}

func TestExecute_POST_Form_StringBody(t *testing.T) {
	var receivedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewDefaultHttpClient(1000, 5000)
	resp, err := client.Execute(&domain.HttpRequest{
		Method:      enums.HttpMethodPost,
		URL:         server.URL,
		Body:        "name=foo&age=30",
		ContentType: enums.ContentTypeForm,
	})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if string(receivedBody) != "name=foo&age=30" {
		t.Errorf("body = %q, want %q", string(receivedBody), "name=foo&age=30")
	}
}

func TestExecute_POST_DefaultContentType_StringBody(t *testing.T) {
	var receivedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewDefaultHttpClient(1000, 5000)
	resp, err := client.Execute(&domain.HttpRequest{
		Method:      enums.HttpMethodPost,
		URL:         server.URL,
		Body:        "raw text body",
		ContentType: "",
	})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if string(receivedBody) != "raw text body" {
		t.Errorf("body = %q, want %q", string(receivedBody), "raw text body")
	}
}

func TestExecute_POST_XML_ContentType(t *testing.T) {
	var receivedCT string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		receivedCT = r.Header.Get(constants.HeaderContentType)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewDefaultHttpClient(1000, 5000)
	resp, err := client.Execute(&domain.HttpRequest{
		Method:      enums.HttpMethodPost,
		URL:         server.URL,
		Body:        "<xml>data</xml>",
		ContentType: enums.ContentTypeXml,
	})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if receivedCT != constants.ContentTypeXml {
		t.Errorf("Content-Type = %q, want %q", receivedCT, constants.ContentTypeXml)
	}
}

func TestExecute_QueryParams(t *testing.T) {
	var receivedQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewDefaultHttpClient(1000, 5000)
	resp, err := client.Execute(&domain.HttpRequest{
		Method: enums.HttpMethodGet,
		URL:    server.URL,
		QueryParams: url.Values{
			"foo": {"bar"},
			"baz": {"qux", "quux"},
		},
	})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	parsed, err := url.ParseQuery(receivedQuery)
	if err != nil {
		t.Fatalf("failed to parse query: %v", err)
	}
	if parsed.Get("foo") != "bar" {
		t.Errorf("query foo = %q, want %q", parsed.Get("foo"), "bar")
	}
	if len(parsed["baz"]) != 2 {
		t.Errorf("query baz should have 2 values, got %d", len(parsed["baz"]))
	}
}

func TestExecute_Headers(t *testing.T) {
	var receivedCustom string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedCustom = r.Header.Get("X-Custom-Header")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewDefaultHttpClient(1000, 5000)
	resp, err := client.Execute(&domain.HttpRequest{
		Method: enums.HttpMethodGet,
		URL:    server.URL,
		Headers: map[string]string{
			"X-Custom-Header": "test-value",
		},
	})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if receivedCustom != "test-value" {
		t.Errorf("X-Custom-Header = %q, want %q", receivedCustom, "test-value")
	}
}

func TestExecute_UserAgent(t *testing.T) {
	var receivedUA string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedUA = r.Header.Get(constants.HeaderUserAgent)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewDefaultHttpClient(1000, 5000)
	resp, err := client.Execute(&domain.HttpRequest{
		Method: enums.HttpMethodGet,
		URL:    server.URL,
	})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if !strings.HasPrefix(receivedUA, "cloud-idaas-go-sdk/") {
		t.Errorf("User-Agent = %q, want prefix %q", receivedUA, "cloud-idaas-go-sdk/")
	}
}

func TestExecute_UserAgent_Override(t *testing.T) {
	var receivedUA string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedUA = r.Header.Get(constants.HeaderUserAgent)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewDefaultHttpClient(1000, 5000)
	resp, err := client.Execute(&domain.HttpRequest{
		Method: enums.HttpMethodGet,
		URL:    server.URL,
		Headers: map[string]string{
			constants.HeaderUserAgent: "my-app/1.0",
		},
	})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if receivedUA != "my-app/1.0" {
		t.Errorf("User-Agent = %q, want %q (caller should override)", receivedUA, "my-app/1.0")
	}
}

func TestExecute_ResponseBody_LargeBody(t *testing.T) {
	largeBody := strings.Repeat("A", 64*1024)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(largeBody))
	}))
	defer server.Close()

	client := NewDefaultHttpClient(1000, 5000)
	resp, err := client.Execute(&domain.HttpRequest{
		Method: enums.HttpMethodGet,
		URL:    server.URL,
	})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if len(resp.Body) != len(largeBody) {
		t.Errorf("Body length = %d, want %d", len(resp.Body), len(largeBody))
	}
	if string(resp.Body) != largeBody {
		t.Error("Body content mismatch")
	}
}

func TestExecute_InvalidURL(t *testing.T) {
	client := NewDefaultHttpClient(1000, 1000)

	// "%zz" is an invalid percent-encoding that url.Parse will reject.
	_, err := client.Execute(&domain.HttpRequest{
		Method:      enums.HttpMethodPost,
		URL:         "http://example.com/path%zz",
		Body:        "test",
		ContentType: "",
		QueryParams: url.Values{"q": {"v"}},
	})
	if err == nil {
		t.Fatal("expected error for invalid URL with query params")
	}
	httpErr, ok := err.(*errors.HttpError)
	if !ok {
		t.Fatalf("error type = %T, want *errors.HttpError", err)
	}
	if httpErr.Code != constants.InvalidURL {
		t.Errorf("error code = %q, want %q", httpErr.Code, constants.InvalidURL)
	}
}

func TestExecute_JSONMarshalError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewDefaultHttpClient(1000, 1000)
	// A channel cannot be JSON-marshaled.
	_, err := client.Execute(&domain.HttpRequest{
		Method:      enums.HttpMethodPost,
		URL:         server.URL,
		Body:        make(chan int),
		ContentType: enums.ContentTypeJson,
	})
	if err == nil {
		t.Fatal("expected error for unmarshalable body")
	}
	encErr, ok := err.(*errors.EncodingError)
	if !ok {
		t.Fatalf("error type = %T, want *errors.EncodingError", err)
	}
	if encErr.Code != constants.EncodeFailed {
		t.Errorf("error code = %q, want %q", encErr.Code, constants.EncodeFailed)
	}
}

func TestExecuteContext_ContextCancelled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	client := NewDefaultHttpClient(10000, 10000)
	_, err := client.ExecuteContext(ctx, &domain.HttpRequest{
		Method: enums.HttpMethodGet,
		URL:    server.URL,
	})
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
	httpErr, ok := err.(*errors.HttpError)
	if !ok {
		t.Fatalf("error type = %T, want *errors.HttpError", err)
	}
	if httpErr.Code != constants.ClientError {
		t.Errorf("error code = %q, want %q (context cancelled -> ClientError)", httpErr.Code, constants.ClientError)
	}
	if !stderrors.Is(httpErr, context.Canceled) {
		t.Error("error chain should contain context.Canceled")
	}
}

func TestExecuteContext_ContextDeadlineExceeded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	client := NewDefaultHttpClient(10000, 10000)
	_, err := client.ExecuteContext(ctx, &domain.HttpRequest{
		Method: enums.HttpMethodGet,
		URL:    server.URL,
	})
	if err == nil {
		t.Fatal("expected error for deadline exceeded")
	}
	httpErr, ok := err.(*errors.HttpError)
	if !ok {
		t.Fatalf("error type = %T, want *errors.HttpError", err)
	}
	if httpErr.Code != constants.ConnectTimeOut {
		t.Errorf("error code = %q, want %q (deadline exceeded -> ConnectTimeOut)", httpErr.Code, constants.ConnectTimeOut)
	}
	if !stderrors.Is(httpErr, context.DeadlineExceeded) {
		t.Error("error chain should contain context.DeadlineExceeded")
	}
}

func TestExecute_TLS_Error(t *testing.T) {
	// httptest.NewTLSServer uses a self-signed certificate.
	// A client with InsecureSkipVerify=false should fail TLS verification.
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewDefaultHttpClient(1000, 5000) // 默认安全配置：不跳过证书校验
	_, err := client.Execute(&domain.HttpRequest{
		Method: enums.HttpMethodGet,
		URL:    server.URL,
	})
	if err == nil {
		t.Skip("TLS error not triggered (environment may trust the test cert)")
	}
	httpErr, ok := err.(*errors.HttpError)
	if !ok {
		t.Fatalf("error type = %T, want *errors.HttpError", err)
	}
	if httpErr.Code != constants.TlsHandshakeFailed {
		t.Errorf("error code = %q, want %q", httpErr.Code, constants.TlsHandshakeFailed)
	}
}

func TestExecute_TLS_InsecureSkipVerify(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	// With insecureSkipVerify=true, the TLS test server should be accessible.
	client := NewDefaultHttpClientWithOptions(1000, 5000, true)
	resp, err := client.Execute(&domain.HttpRequest{
		Method: enums.HttpMethodGet,
		URL:    server.URL,
	})
	if err != nil {
		t.Fatalf("Execute with InsecureSkipVerify returned error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if string(resp.Body) != "ok" {
		t.Errorf("Body = %q, want %q", string(resp.Body), "ok")
	}
}

func TestGet(t *testing.T) {
	var receivedMethod string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMethod = r.Method
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("get response"))
	}))
	defer server.Close()

	client := NewDefaultHttpClient(1000, 5000)
	resp, err := client.Get(server.URL, map[string]string{"X-Test": "1"})
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	if receivedMethod != "GET" {
		t.Errorf("method = %q, want GET", receivedMethod)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if string(resp.Body) != "get response" {
		t.Errorf("Body = %q, want %q", string(resp.Body), "get response")
	}
}

func TestPost(t *testing.T) {
	var receivedMethod string
	var receivedCT string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMethod = r.Method
		receivedCT = r.Header.Get(constants.HeaderContentType)
		_, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("created"))
	}))
	defer server.Close()

	client := NewDefaultHttpClient(1000, 5000)
	resp, err := client.Post(server.URL, nil, map[string]string{"key": "value"})
	if err != nil {
		t.Fatalf("Post returned error: %v", err)
	}
	if receivedMethod != "POST" {
		t.Errorf("method = %q, want POST", receivedMethod)
	}
	if receivedCT != constants.ContentTypeJson {
		t.Errorf("Content-Type = %q, want %q", receivedCT, constants.ContentTypeJson)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusCreated)
	}
	if string(resp.Body) != "created" {
		t.Errorf("Body = %q, want %q", string(resp.Body), "created")
	}
}

func TestClassifyHttpError(t *testing.T) {
	// Pre-constructed errors for table-driven tests.
	dnsErr := &net.DNSError{Err: "no such host", Name: "nonexistent.invalid"}
	dnsOpErr := &net.OpError{Op: "dial", Net: "tcp", Err: dnsErr}
	resetOpErr := &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNRESET}
	timeoutNetErr := &mockNetError{msg: "i/o timeout", timeout: true}
	timeoutOpErr := &net.OpError{Op: "dial", Net: "tcp", Err: timeoutNetErr}
	// 使用值类型（非指针）：classifyHttpError 的 stderrors.As 目标也是值类型，
	// 因为 x509 的 Error() 方法使用值接收器，实际错误返回的是值而非指针。
	// HostnameError.Error() 会访问 Certificate.hasSANExtension()，必须提供非 nil 的 Certificate。
	unknownAuthErr := x509.UnknownAuthorityError{}
	certInvalidErr := x509.CertificateInvalidError{}
	hostnameErr := x509.HostnameError{Certificate: &x509.Certificate{}, Host: "example.com"}

	tests := []struct {
		name        string
		err         error
		wantCode    string
		wantMessage string
	}{
		{
			name:        "context canceled",
			err:         context.Canceled,
			wantCode:    constants.ClientError,
			wantMessage: "request cancelled by context",
		},
		{
			name:        "context deadline exceeded",
			err:         context.DeadlineExceeded,
			wantCode:    constants.ConnectTimeOut,
			wantMessage: "request deadline exceeded",
		},
		{
			name:        "wrapped context canceled",
			err:         fmt.Errorf("wrap: %w", context.Canceled),
			wantCode:    constants.ClientError,
			wantMessage: "request cancelled by context",
		},
		{
			name:        "x509 unknown authority",
			err:         unknownAuthErr,
			wantCode:    constants.TlsHandshakeFailed,
			wantMessage: "TLS certificate verification failed",
		},
		{
			name:        "x509 certificate invalid",
			err:         certInvalidErr,
			wantCode:    constants.TlsHandshakeFailed,
			wantMessage: "TLS certificate verification failed",
		},
		{
			name:        "x509 hostname mismatch",
			err:         hostnameErr,
			wantCode:    constants.TlsHandshakeFailed,
			wantMessage: "TLS certificate verification failed",
		},
		{
			name:        "tls record header error",
			err:         tls.RecordHeaderError{Msg: "tls: first record does not look like a TLS handshake"},
			wantCode:    constants.TlsHandshakeFailed,
			wantMessage: "TLS handshake failed",
		},
		{
			name:        "DNS lookup failure via OpError",
			err:         dnsOpErr,
			wantCode:    constants.DnsLookupFailed,
			wantMessage: "DNS resolution failed",
		},
		{
			name:        "connection reset via OpError",
			err:         resetOpErr,
			wantCode:    constants.ConnectionReset,
			wantMessage: "connection reset by peer",
		},
		{
			name:        "timeout via OpError",
			err:         timeoutOpErr,
			wantCode:    constants.ConnectTimeOut,
			wantMessage: "connection timed out",
		},
		{
			name:        "timeout via generic net.Error",
			err:         timeoutNetErr,
			wantCode:    constants.ConnectTimeOut,
			wantMessage: "network operation timed out",
		},
		{
			name:        "generic client error",
			err:         fmt.Errorf("some unknown error"),
			wantCode:    constants.ClientError,
			wantMessage: "HTTP request failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyHttpError(tt.err)
			httpErr, ok := got.(*errors.HttpError)
			if !ok {
				t.Fatalf("classifyHttpError returned %T, want *errors.HttpError", got)
			}
			if httpErr.Code != tt.wantCode {
				t.Errorf("Code = %q, want %q", httpErr.Code, tt.wantCode)
			}
			if !strings.HasPrefix(httpErr.Message, tt.wantMessage) {
				t.Errorf("Message = %q, want prefix %q", httpErr.Message, tt.wantMessage)
			}
			// Verify the original error is preserved in the chain.
			if httpErr.Cause == nil {
				t.Error("Cause should not be nil")
			}
		})
	}
}

func TestClassifyReadBodyError(t *testing.T) {
	timeoutErr := &mockNetError{msg: "read timeout", timeout: true}

	tests := []struct {
		name        string
		err         error
		statusCode  int
		wantCode    string
		wantMessage string
	}{
		{
			name:        "context canceled",
			err:         context.Canceled,
			statusCode:  200,
			wantCode:    constants.ClientError,
			wantMessage: "read cancelled by context",
		},
		{
			name:        "context deadline exceeded",
			err:         context.DeadlineExceeded,
			statusCode:  200,
			wantCode:    constants.ReadTimeOut,
			wantMessage: "read deadline exceeded",
		},
		{
			name:        "EOF",
			err:         io.EOF,
			statusCode:  200,
			wantCode:    constants.ResponseTruncated,
			wantMessage: "response body truncated",
		},
		{
			name:        "unexpected EOF",
			err:         io.ErrUnexpectedEOF,
			statusCode:  200,
			wantCode:    constants.ResponseTruncated,
			wantMessage: "response body truncated",
		},
		{
			name:        "connection reset (ECONNRESET)",
			err:         fmt.Errorf("read: %w", syscall.ECONNRESET),
			statusCode:  200,
			wantCode:    constants.ConnectionReset,
			wantMessage: "connection reset while reading response",
		},
		{
			name:        "connection reset (EPIPE)",
			err:         fmt.Errorf("write: %w", syscall.EPIPE),
			statusCode:  200,
			wantCode:    constants.ConnectionReset,
			wantMessage: "connection reset while reading response",
		},
		{
			name:        "timeout",
			err:         timeoutErr,
			statusCode:  200,
			wantCode:    constants.ReadTimeOut,
			wantMessage: "read timed out",
		},
		{
			name:        "generic error fallback",
			err:         fmt.Errorf("some read error"),
			statusCode:  500,
			wantCode:    constants.ClientError,
			wantMessage: "failed to read response body",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyReadBodyError(tt.err, tt.statusCode)
			httpErr, ok := got.(*errors.HttpError)
			if !ok {
				t.Fatalf("classifyReadBodyError returned %T, want *errors.HttpError", got)
			}
			if httpErr.Code != tt.wantCode {
				t.Errorf("Code = %q, want %q", httpErr.Code, tt.wantCode)
			}
			if !strings.HasPrefix(httpErr.Message, tt.wantMessage) {
				t.Errorf("Message = %q, want prefix %q", httpErr.Message, tt.wantMessage)
			}
			if httpErr.StatusCode != tt.statusCode {
				t.Errorf("StatusCode = %d, want %d", httpErr.StatusCode, tt.statusCode)
			}
		})
	}
}

func TestIsConnectionReset(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"ECONNRESET direct", syscall.ECONNRESET, true},
		{"EPIPE direct", syscall.EPIPE, true},
		{"ECONNRESET wrapped", fmt.Errorf("dial: %w", syscall.ECONNRESET), true},
		{"EPIPE wrapped", fmt.Errorf("write: %w", syscall.EPIPE), true},
		{"string 'connection reset by peer'", fmt.Errorf("read: connection reset by peer"), true},
		{"string 'broken pipe'", fmt.Errorf("write: broken pipe"), true},
		{"ECONNREFUSED (not reset)", syscall.ECONNREFUSED, false},
		{"ETIMEDOUT (not reset)", syscall.ETIMEDOUT, false},
		{"generic error", fmt.Errorf("some other error"), false},
		{"double-wrapped ECONNRESET", fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", syscall.ECONNRESET)), true},
		{"string without reset keywords", fmt.Errorf("connection refused"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isConnectionReset(tt.err)
			if got != tt.want {
				t.Errorf("isConnectionReset(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestExecute_ConnectionRefused(t *testing.T) {
	// Start a server, get its address, then close it to simulate connection refused.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	addr := server.Listener.Addr().String()
	server.Close()

	client := NewDefaultHttpClient(1000, 2000)
	_, err := client.Execute(&domain.HttpRequest{
		Method: enums.HttpMethodGet,
		URL:    "http://" + addr + "/",
	})
	if err == nil {
		t.Fatal("expected error for connection refused")
	}
	httpErr, ok := err.(*errors.HttpError)
	if !ok {
		t.Fatalf("error type = %T, want *errors.HttpError", err)
	}
	// Connection refused could be classified as ClientError (fallback) or a specific code.
	// The exact classification depends on the OS; we just verify it's an HttpError.
	if httpErr.Code == "" {
		t.Error("error code should not be empty")
	}
}

func TestExecute_StatusCode_NotModified(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotModified)
	}))
	defer server.Close()

	client := NewDefaultHttpClient(1000, 5000)
	resp, err := client.Execute(&domain.HttpRequest{
		Method: enums.HttpMethodGet,
		URL:    server.URL,
	})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if resp.StatusCode != http.StatusNotModified {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusNotModified)
	}
	if resp.IsSuccess() {
		t.Error("304 should not be IsSuccess (not in 200-299 range)")
	}
}

func TestExecute_StatusCode_NoBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := NewDefaultHttpClient(1000, 5000)
	resp, err := client.Execute(&domain.HttpRequest{
		Method: enums.HttpMethodGet,
		URL:    server.URL,
	})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
	if len(resp.Body) != 0 {
		t.Errorf("Body length = %d, want 0", len(resp.Body))
	}
	if !resp.IsSuccess() {
		t.Error("204 should be IsSuccess")
	}
}

func TestExecute_DelegatesToExecuteContext(t *testing.T) {
	// Execute should use context.Background() internally.
	// Verify by making a simple request that succeeds.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewDefaultHttpClient(1000, 5000)
	resp, err := client.Execute(&domain.HttpRequest{
		Method: enums.HttpMethodGet,
		URL:    server.URL,
	})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if resp == nil {
		t.Error("resp should not be nil")
	}
}

// TestSecureCheckRedirect_StripsBodyCrossHost verifies that on a cross-host
// redirect the request body, Content-Length and Content-Type are stripped in
// addition to Authorization/Cookie headers. This prevents client_secret_post
// (whose secret lives in the body) from being replayed to an untrusted host.
func TestSecureCheckRedirect_StripsBodyCrossHost(t *testing.T) {
	body := strings.NewReader("client_secret=super-secret&grant_type=client_credentials")
	req := httptest.NewRequest(http.MethodPost, "https://evil.example.com/token", body)
	req.Header.Set(constants.HeaderAuthorization, "Bearer leak")
	req.Header.Set(constants.HeaderCookie, "session=leak")
	req.Header.Set(constants.HeaderContentType, constants.ContentTypeFormUrlEncoded)
	req.ContentLength = int64(body.Len())

	prev := httptest.NewRequest(http.MethodPost, "https://token.idaas.example.com/token", http.NoBody)
	via := []*http.Request{prev}

	if err := secureCheckRedirect(req, via); err != nil {
		t.Fatalf("secureCheckRedirect returned error: %v", err)
	}

	if got := req.Header.Get(constants.HeaderAuthorization); got != "" {
		t.Errorf("Authorization header not stripped on cross-host redirect: %q", got)
	}
	if got := req.Header.Get(constants.HeaderCookie); got != "" {
		t.Errorf("Cookie header not stripped on cross-host redirect: %q", got)
	}
	if got := req.Header.Get(constants.HeaderContentType); got != "" {
		t.Errorf("Content-Type not stripped on cross-host redirect: %q", got)
	}
	if req.Body != http.NoBody {
		t.Errorf("body not replaced with http.NoBody on cross-host redirect: got %T", req.Body)
	}
	if req.ContentLength != 0 {
		t.Errorf("ContentLength not zeroed on cross-host redirect: got %d", req.ContentLength)
	}
	if req.GetBody != nil {
		t.Errorf("GetBody not cleared on cross-host redirect")
	}
}

// TestSecureCheckRedirect_PreservesBodySameHost verifies that a same-host
// redirect keeps the body and headers intact (credentials stay within the
// trusted host boundary).
func TestSecureCheckRedirect_PreservesBodySameHost(t *testing.T) {
	body := strings.NewReader("client_secret=super-secret&grant_type=client_credentials")
	req := httptest.NewRequest(http.MethodPost, "https://idaas.example.com/token", body)
	req.Header.Set(constants.HeaderAuthorization, "Bearer keep")
	req.Header.Set(constants.HeaderContentType, constants.ContentTypeFormUrlEncoded)
	req.ContentLength = int64(body.Len())

	prev := httptest.NewRequest(http.MethodPost, "https://idaas.example.com/oauth/token", http.NoBody)
	via := []*http.Request{prev}

	if err := secureCheckRedirect(req, via); err != nil {
		t.Fatalf("secureCheckRedirect returned error: %v", err)
	}

	if got := req.Header.Get(constants.HeaderAuthorization); got != "Bearer keep" {
		t.Errorf("Authorization should be preserved on same-host redirect, got %q", got)
	}
	if got := req.Header.Get(constants.HeaderContentType); got != constants.ContentTypeFormUrlEncoded {
		t.Errorf("Content-Type should be preserved on same-host redirect, got %q", got)
	}
	if req.ContentLength != int64(body.Len()) {
		t.Errorf("ContentLength should be preserved on same-host redirect, got %d", req.ContentLength)
	}
}

// TestSecureCheckRedirect_MaxRedirects verifies the hop limit.
func TestSecureCheckRedirect_MaxRedirects(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://idaas.example.com/token", http.NoBody)
	via := make([]*http.Request, maxRedirects)
	for i := range via {
		via[i] = httptest.NewRequest(http.MethodGet, "https://idaas.example.com/token", http.NoBody)
	}
	if err := secureCheckRedirect(req, via); err == nil {
		t.Error("secureCheckRedirect should error after maxRedirects")
	}
}

// TestSecureCheckRedirect_StripsOnSchemeDowngrade verifies that a same-host
// https→http redirect is treated as insecure: Authorization/Cookie are stripped
// and, for body-preserving redirects (307/308 method match), the body and
// Content-Type/Content-Length are dropped to prevent client_secret replay.
func TestSecureCheckRedirect_StripsOnSchemeDowngrade(t *testing.T) {
	body := strings.NewReader("client_secret=super-secret&grant_type=client_credentials")
	req := httptest.NewRequest(http.MethodPost, "http://idaas.example.com/token", body)
	req.Header.Set(constants.HeaderAuthorization, "Bearer leak")
	req.Header.Set(constants.HeaderCookie, "session=leak")
	req.Header.Set(constants.HeaderContentType, constants.ContentTypeFormUrlEncoded)
	req.Header.Set("Content-Length", fmt.Sprintf("%d", body.Len()))
	req.ContentLength = int64(body.Len())

	prev := httptest.NewRequest(http.MethodPost, "https://idaas.example.com/oauth/token", http.NoBody)
	via := []*http.Request{prev}

	if err := secureCheckRedirect(req, via); err != nil {
		t.Fatalf("secureCheckRedirect returned error: %v", err)
	}

	if got := req.Header.Get(constants.HeaderAuthorization); got != "" {
		t.Errorf("Authorization header not stripped on scheme downgrade: %q", got)
	}
	if got := req.Header.Get(constants.HeaderCookie); got != "" {
		t.Errorf("Cookie header not stripped on scheme downgrade: %q", got)
	}
	if got := req.Header.Get(constants.HeaderContentType); got != "" {
		t.Errorf("Content-Type not stripped on scheme downgrade: %q", got)
	}
	if got := req.Header.Get("Content-Length"); got != "" {
		t.Errorf("Content-Length header not stripped on scheme downgrade: %q", got)
	}
	if req.Body != http.NoBody {
		t.Errorf("body not replaced with http.NoBody on scheme downgrade: got %T", req.Body)
	}
	if req.ContentLength != 0 {
		t.Errorf("ContentLength not zeroed on scheme downgrade: got %d", req.ContentLength)
	}
	if req.GetBody != nil {
		t.Error("GetBody not cleared on scheme downgrade")
	}
}

// TestSecureCheckRedirect_PreservesOnSchemeUpgrade verifies that a same-host
// http→https redirect is NOT treated as insecure — headers and body stay intact.
func TestSecureCheckRedirect_PreservesOnSchemeUpgrade(t *testing.T) {
	body := strings.NewReader("client_secret=super-secret&grant_type=client_credentials")
	req := httptest.NewRequest(http.MethodPost, "https://idaas.example.com/token", body)
	req.Header.Set(constants.HeaderAuthorization, "Bearer keep")
	req.Header.Set(constants.HeaderContentType, constants.ContentTypeFormUrlEncoded)
	req.ContentLength = int64(body.Len())

	prev := httptest.NewRequest(http.MethodPost, "http://idaas.example.com/oauth/token", http.NoBody)
	via := []*http.Request{prev}

	if err := secureCheckRedirect(req, via); err != nil {
		t.Fatalf("secureCheckRedirect returned error: %v", err)
	}

	if got := req.Header.Get(constants.HeaderAuthorization); got != "Bearer keep" {
		t.Errorf("Authorization should be preserved on scheme upgrade, got %q", got)
	}
	if got := req.Header.Get(constants.HeaderContentType); got != constants.ContentTypeFormUrlEncoded {
		t.Errorf("Content-Type should be preserved on scheme upgrade, got %q", got)
	}
	if req.ContentLength != int64(body.Len()) {
		t.Errorf("ContentLength should be preserved on scheme upgrade, got %d", req.ContentLength)
	}
}

// TestSecureCheckRedirect_StripsHeadersOnlyOnGetRedirect verifies that on a
// cross-host redirect where the method was changed to GET (301/302/303),
// Authorization/Cookie are stripped but body-related fields are left alone
// (Go's redirect logic already dropped the body for GET).
func TestSecureCheckRedirect_StripsHeadersOnlyOnGetRedirect(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://evil.example.com/token", http.NoBody)
	req.Header.Set(constants.HeaderAuthorization, "Bearer leak")
	req.Header.Set(constants.HeaderCookie, "session=leak")

	prev := httptest.NewRequest(http.MethodPost, "https://idaas.example.com/token", http.NoBody)
	via := []*http.Request{prev}

	if err := secureCheckRedirect(req, via); err != nil {
		t.Fatalf("secureCheckRedirect returned error: %v", err)
	}

	if got := req.Header.Get(constants.HeaderAuthorization); got != "" {
		t.Errorf("Authorization header not stripped on cross-host GET redirect: %q", got)
	}
	if got := req.Header.Get(constants.HeaderCookie); got != "" {
		t.Errorf("Cookie header not stripped on cross-host GET redirect: %q", got)
	}
}
