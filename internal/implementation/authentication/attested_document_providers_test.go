package authentication

import (
	"context"
	"testing"

	"github.com/cloud-idaas/idaas-go-core-sdk/domain"
	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
)

// --- AlibabaCloudEcsAttestedDocumentProvider tests ---

func TestNewAlibabaCloudEcsAttestedDocumentProvider(t *testing.T) {
	mock := &mockAuthHttpClient{}
	p := NewAlibabaCloudEcsAttestedDocumentProvider(mock, "inst-123", 0)
	if p == nil {
		t.Fatal("expected non-nil provider")
	}
	if p.idaasInstanceId != "inst-123" {
		t.Errorf("expected idaasInstanceId 'inst-123', got '%s'", p.idaasInstanceId)
	}
	if p.httpClient != mock {
		t.Error("httpClient mismatch")
	}
	if p.defaultDocumentEffectiveSeconds <= 0 {
		t.Errorf("expected positive TTL, got %d", p.defaultDocumentEffectiveSeconds)
	}
	if p.tokenUrl == "" {
		t.Error("expected non-empty tokenUrl")
	}
	if p.pkcs7UrlTemplate == "" {
		t.Error("expected non-empty pkcs7UrlTemplate")
	}
}

func TestNewAlibabaCloudEcsAttestedDocumentProvider_CustomTtl(t *testing.T) {
	mock := &mockAuthHttpClient{}
	p := NewAlibabaCloudEcsAttestedDocumentProvider(mock, "inst-123", 7200)
	if p.defaultDocumentEffectiveSeconds != 7200 {
		t.Errorf("expected TTL 7200, got %d", p.defaultDocumentEffectiveSeconds)
	}
}

func TestAlibabaCloudEcsProvider_GetAttestedDocument_Success(t *testing.T) {
	mock := &mockAuthHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			if req.Method == enums.HttpMethodPut {
				return &domain.HttpResponse{StatusCode: 200, Body: []byte("metadata-token-value")}, nil
			}
			if req.Method == enums.HttpMethodGet {
				return &domain.HttpResponse{StatusCode: 200, Body: []byte("pkcs7-attested-doc")}, nil
			}
			return &domain.HttpResponse{StatusCode: 500, Body: []byte("unexpected")}, nil
		},
	}
	p := NewAlibabaCloudEcsAttestedDocumentProvider(mock, "inst-123", 0)
	doc, err := p.GetAttestedDocument()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if doc != "pkcs7-attested-doc" {
		t.Errorf("expected 'pkcs7-attested-doc', got '%s'", doc)
	}
}

func TestAlibabaCloudEcsProvider_GetAttestedDocument_EmptyInstanceId(t *testing.T) {
	mock := &mockAuthHttpClient{}
	p := NewAlibabaCloudEcsAttestedDocumentProvider(mock, "", 0)
	_, err := p.GetAttestedDocument()
	if err == nil {
		t.Fatal("expected error for empty instance ID")
	}
}

func TestAlibabaCloudEcsProvider_GetAttestedDocument_TokenFetchError(t *testing.T) {
	mock := &mockAuthHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 403, Body: []byte("forbidden")}, nil
		},
	}
	p := NewAlibabaCloudEcsAttestedDocumentProvider(mock, "inst-123", 0)
	_, err := p.GetAttestedDocument()
	if err == nil {
		t.Fatal("expected error for failed token fetch")
	}
}

func TestAlibabaCloudEcsProvider_GetAttestedDocument_DocFetchError(t *testing.T) {
	callCount := 0
	mock := &mockAuthHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			callCount++
			if callCount == 1 {
				return &domain.HttpResponse{StatusCode: 200, Body: []byte("metadata-token")}, nil
			}
			return &domain.HttpResponse{StatusCode: 500, Body: []byte("server error")}, nil
		},
	}
	p := NewAlibabaCloudEcsAttestedDocumentProvider(mock, "inst-123", 0)
	_, err := p.GetAttestedDocument()
	if err == nil {
		t.Fatal("expected error for failed doc fetch")
	}
}

func TestAlibabaCloudEcsProvider_FetchMetadataToken_Success(t *testing.T) {
	mock := &mockAuthHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			if req.Method != enums.HttpMethodPut {
				t.Errorf("expected PUT method, got %s", req.Method)
			}
			return &domain.HttpResponse{StatusCode: 200, Body: []byte("token-123")}, nil
		},
	}
	p := NewAlibabaCloudEcsAttestedDocumentProvider(mock, "inst-123", 0)
	token, err := p.fetchMetadataToken(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "token-123" {
		t.Errorf("expected 'token-123', got '%s'", token)
	}
}

func TestAlibabaCloudEcsProvider_FetchMetadataToken_HttpError(t *testing.T) {
	mock := &mockAuthHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 404, Body: []byte("not found")}, nil
		},
	}
	p := NewAlibabaCloudEcsAttestedDocumentProvider(mock, "inst-123", 0)
	_, err := p.fetchMetadataToken(context.Background())
	if err == nil {
		t.Fatal("expected error for HTTP 404")
	}
}

// --- AwsEc2AttestedDocumentProvider tests ---

func TestNewAwsEc2AttestedDocumentProvider(t *testing.T) {
	mock := &mockAuthHttpClient{}
	p := NewAwsEc2AttestedDocumentProvider(mock, 0)
	if p == nil {
		t.Fatal("expected non-nil provider")
	}
	if p.httpClient != mock {
		t.Error("httpClient mismatch")
	}
	if p.tokenTtlSeconds <= 0 {
		t.Errorf("expected positive TTL, got %d", p.tokenTtlSeconds)
	}
	if p.tokenUrl == "" {
		t.Error("expected non-empty tokenUrl")
	}
	if p.pkcs7Url == "" {
		t.Error("expected non-empty pkcs7Url")
	}
}

func TestNewAwsEc2AttestedDocumentProvider_CustomTtl(t *testing.T) {
	mock := &mockAuthHttpClient{}
	p := NewAwsEc2AttestedDocumentProvider(mock, 300)
	if p.tokenTtlSeconds != 300 {
		t.Errorf("expected TTL 300, got %d", p.tokenTtlSeconds)
	}
}

func TestAwsEc2Provider_GetAttestedDocument_Success(t *testing.T) {
	mock := &mockAuthHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			if req.Method == enums.HttpMethodPut {
				return &domain.HttpResponse{StatusCode: 200, Body: []byte("aws-metadata-token")}, nil
			}
			if req.Method == enums.HttpMethodGet {
				return &domain.HttpResponse{StatusCode: 200, Body: []byte("MIIB\nIYB\nZkY=\n")}, nil
			}
			return &domain.HttpResponse{StatusCode: 500, Body: []byte("err")}, nil
		},
	}
	p := NewAwsEc2AttestedDocumentProvider(mock, 0)
	doc, err := p.GetAttestedDocument()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if doc != "MIIBIYBZkY=" {
		t.Errorf("expected stripped PKCS7, got '%s'", doc)
	}
}

func TestAwsEc2Provider_GetAttestedDocument_TokenFetchError(t *testing.T) {
	mock := &mockAuthHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 403, Body: []byte("forbidden")}, nil
		},
	}
	p := NewAwsEc2AttestedDocumentProvider(mock, 0)
	_, err := p.GetAttestedDocument()
	if err == nil {
		t.Fatal("expected error for failed token fetch")
	}
}

func TestAwsEc2Provider_GetAttestedDocument_Pkcs7FetchError(t *testing.T) {
	callCount := 0
	mock := &mockAuthHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			callCount++
			if callCount == 1 {
				return &domain.HttpResponse{StatusCode: 200, Body: []byte("token")}, nil
			}
			return &domain.HttpResponse{StatusCode: 500, Body: []byte("err")}, nil
		},
	}
	p := NewAwsEc2AttestedDocumentProvider(mock, 0)
	_, err := p.GetAttestedDocument()
	if err == nil {
		t.Fatal("expected error for failed pkcs7 fetch")
	}
}

func TestAwsEc2Provider_FetchMetadataToken_Success(t *testing.T) {
	mock := &mockAuthHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 200, Body: []byte("imds-token")}, nil
		},
	}
	p := NewAwsEc2AttestedDocumentProvider(mock, 0)
	token, err := p.fetchMetadataToken(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "imds-token" {
		t.Errorf("expected 'imds-token', got '%s'", token)
	}
}

func TestAwsEc2Provider_FetchMetadataToken_Error(t *testing.T) {
	mock := &mockAuthHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 500, Body: []byte("err")}, nil
		},
	}
	p := NewAwsEc2AttestedDocumentProvider(mock, 0)
	_, err := p.fetchMetadataToken(context.Background())
	if err == nil {
		t.Fatal("expected error for HTTP 500")
	}
}

func TestAwsEc2Provider_FetchPkcs7_Success(t *testing.T) {
	mock := &mockAuthHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 200, Body: []byte("pkcs7-data")}, nil
		},
	}
	p := NewAwsEc2AttestedDocumentProvider(mock, 0)
	pkcs7, err := p.fetchPkcs7(context.Background(), "metadata-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pkcs7 != "pkcs7-data" {
		t.Errorf("expected 'pkcs7-data', got '%s'", pkcs7)
	}
}

func TestAwsEc2Provider_FetchPkcs7_Error(t *testing.T) {
	mock := &mockAuthHttpClient{
		executeFn: func(req *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 500, Body: []byte("err")}, nil
		},
	}
	p := NewAwsEc2AttestedDocumentProvider(mock, 0)
	_, err := p.fetchPkcs7(context.Background(), "token")
	if err == nil {
		t.Fatal("expected error for HTTP 500")
	}
}

// --- stripWhitespace tests ---

func TestStripWhitespace(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"hello", "hello"},
		{"hello world", "helloworld"},
		{"hello\nworld", "helloworld"},
		{"hello\r\nworld", "helloworld"},
		{"hello\tworld", "helloworld"},
		{"\n\r\t hello\nworld\t ", "helloworld"},
		{"", ""},
		{"\n\r\t ", ""},
		{"a\nb\rc\td e", "abcde"},
	}
	for _, tt := range tests {
		got := stripWhitespace(tt.input)
		if got != tt.expected {
			t.Errorf("stripWhitespace(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

// suppress unused import warning
var _ = context.Background
