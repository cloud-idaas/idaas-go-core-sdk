package domain

import (
	"encoding/json"
	"testing"
)

// TestErrResponse_UnmarshalJSON_StandardFormat 测试标准 OAuth2 错误格式解析
func TestErrResponse_UnmarshalJSON_StandardFormat(t *testing.T) {
	jsonData := `{"error": "invalid_token", "error_description": "The access token provided is expired"}`

	var response ErrResponse
	err := json.Unmarshal([]byte(jsonData), &response)
	if err != nil {
		t.Fatalf("UnmarshalJSON failed: %v", err)
	}

	if response.Error != "invalid_token" {
		t.Errorf("Error = %v, want %v", response.Error, "invalid_token")
	}
	if response.ErrorDescription != "The access token provided is expired" {
		t.Errorf("ErrorDescription = %v, want %v", response.ErrorDescription, "The access token provided is expired")
	}
	if response.Code != "" {
		t.Errorf("Code should be empty, got %v", response.Code)
	}
	if response.Message != "" {
		t.Errorf("Message should be empty, got %v", response.Message)
	}
}

// TestErrResponse_UnmarshalJSON_IDaaSFormat 测试 IDaaS 自定义格式解析
func TestErrResponse_UnmarshalJSON_IDaaSFormat(t *testing.T) {
	jsonData := `{"code": "401", "message": "Unauthorized access"}`

	var response ErrResponse
	err := json.Unmarshal([]byte(jsonData), &response)
	if err != nil {
		t.Fatalf("UnmarshalJSON failed: %v", err)
	}

	if response.Code != "401" {
		t.Errorf("Code = %v, want %v", response.Code, "401")
	}
	if response.Message != "Unauthorized access" {
		t.Errorf("Message = %v, want %v", response.Message, "Unauthorized access")
	}
	if response.Error != "" {
		t.Errorf("Error should be empty, got %v", response.Error)
	}
	if response.ErrorDescription != "" {
		t.Errorf("ErrorDescription should be empty, got %v", response.ErrorDescription)
	}
}

// TestErrResponse_UnmarshalJSON_EmptyJSON 测试空 JSON 对象
func TestErrResponse_UnmarshalJSON_EmptyJSON(t *testing.T) {
	jsonData := `{}`

	var response ErrResponse
	err := json.Unmarshal([]byte(jsonData), &response)
	if err != nil {
		t.Fatalf("UnmarshalJSON failed: %v", err)
	}

	if response.Error != "" {
		t.Errorf("Error should be empty, got %v", response.Error)
	}
	if response.ErrorDescription != "" {
		t.Errorf("ErrorDescription should be empty, got %v", response.ErrorDescription)
	}
	if response.Code != "" {
		t.Errorf("Code should be empty, got %v", response.Code)
	}
	if response.Message != "" {
		t.Errorf("Message should be empty, got %v", response.Message)
	}
}

// TestErrResponse_UnmarshalJSON_MixedFormat 测试混合格式（优先使用标准格式）
func TestErrResponse_UnmarshalJSON_MixedFormat(t *testing.T) {
	// 当同时存在两种格式时，标准格式优先
	jsonData := `{"error": "access_denied", "error_description": "Access denied", "code": "403", "message": "Forbidden"}`

	var response ErrResponse
	err := json.Unmarshal([]byte(jsonData), &response)
	if err != nil {
		t.Fatalf("UnmarshalJSON failed: %v", err)
	}

	if response.Error != "access_denied" {
		t.Errorf("Error = %v, want %v", response.Error, "access_denied")
	}
	if response.ErrorDescription != "Access denied" {
		t.Errorf("ErrorDescription = %v, want %v", response.ErrorDescription, "Access denied")
	}
}

// TestErrResponse_GetErrorCode 测试 GetErrorCode 方法
func TestErrResponse_GetErrorCode(t *testing.T) {
	tests := []struct {
		name     string
		response ErrResponse
		want     string
	}{
		{
			name: "标准格式有 error 字段",
			response: ErrResponse{
				Error: "invalid_grant",
				Code:  "400",
			},
			want: "invalid_grant",
		},
		{
			name: "IDaaS 格式只有 code 字段",
			response: ErrResponse{
				Code: "500",
			},
			want: "500",
		},
		{
			name:     "两个字段都为空",
			response: ErrResponse{},
			want:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.response.GetErrorCode()
			if got != tt.want {
				t.Errorf("GetErrorCode() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestErrResponse_GetErrorMessage 测试 GetErrorMessage 方法
func TestErrResponse_GetErrorMessage(t *testing.T) {
	tests := []struct {
		name     string
		response ErrResponse
		want     string
	}{
		{
			name: "标准格式有 error_description 字段",
			response: ErrResponse{
				ErrorDescription: "Token has expired",
				Message:          "Session expired",
			},
			want: "Token has expired",
		},
		{
			name: "IDaaS 格式只有 message 字段",
			response: ErrResponse{
				Message: "Internal server error",
			},
			want: "Internal server error",
		},
		{
			name:     "两个字段都为空",
			response: ErrResponse{},
			want:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.response.GetErrorMessage()
			if got != tt.want {
				t.Errorf("GetErrorMessage() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestHttpResponse_IsSuccess 测试 IsSuccess 方法
func TestHttpResponse_IsSuccess(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		want       bool
	}{
		{
			name:       "200 OK",
			statusCode: 200,
			want:       true,
		},
		{
			name:       "201 Created",
			statusCode: 201,
			want:       true,
		},
		{
			name:       "204 No Content",
			statusCode: 204,
			want:       true,
		},
		{
			name:       "299 成功范围边界",
			statusCode: 299,
			want:       true,
		},
		{
			name:       "199 低于成功范围",
			statusCode: 199,
			want:       false,
		},
		{
			name:       "300 重定向",
			statusCode: 300,
			want:       false,
		},
		{
			name:       "400 Bad Request",
			statusCode: 400,
			want:       false,
		},
		{
			name:       "401 Unauthorized",
			statusCode: 401,
			want:       false,
		},
		{
			name:       "403 Forbidden",
			statusCode: 403,
			want:       false,
		},
		{
			name:       "404 Not Found",
			statusCode: 404,
			want:       false,
		},
		{
			name:       "500 Internal Server Error",
			statusCode: 500,
			want:       false,
		},
		{
			name:       "503 Service Unavailable",
			statusCode: 503,
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := HttpResponse{
				StatusCode: tt.statusCode,
			}
			got := response.IsSuccess()
			if got != tt.want {
				t.Errorf("IsSuccess() with status %d = %v, want %v", tt.statusCode, got, tt.want)
			}
		})
	}
}

// TestHttpResponse_IsSuccess_EdgeCases 测试 IsSuccess 边界情况
func TestHttpResponse_IsSuccess_EdgeCases(t *testing.T) {
	// 测试负数状态码
	response := HttpResponse{
		StatusCode: -1,
	}
	if response.IsSuccess() {
		t.Error("IsSuccess() should return false for negative status code")
	}

	// 测试零状态码
	response = HttpResponse{
		StatusCode: 0,
	}
	if response.IsSuccess() {
		t.Error("IsSuccess() should return false for zero status code")
	}
}

// TestDeviceCodeResponse_JSONFields 测试 DeviceCodeResponse 结构体字段
func TestDeviceCodeResponse_JSONFields(t *testing.T) {
	response := DeviceCodeResponse{
		DeviceCode:              "device_code_123",
		UserCode:                "user_code_456",
		VerificationURI:         "https://example.com/verify",
		VerificationURIComplete: "https://example.com/verify?code=user_code_456",
		ExpiresIn:               600,
		Interval:                5,
	}

	if response.DeviceCode != "device_code_123" {
		t.Errorf("DeviceCode = %v, want %v", response.DeviceCode, "device_code_123")
	}
	if response.UserCode != "user_code_456" {
		t.Errorf("UserCode = %v, want %v", response.UserCode, "user_code_456")
	}
	if response.VerificationURI != "https://example.com/verify" {
		t.Errorf("VerificationURI = %v, want %v", response.VerificationURI, "https://example.com/verify")
	}
	if response.VerificationURIComplete != "https://example.com/verify?code=user_code_456" {
		t.Errorf("VerificationURIComplete = %v, want %v", response.VerificationURIComplete, "https://example.com/verify?code=user_code_456")
	}
	if response.ExpiresIn != 600 {
		t.Errorf("ExpiresIn = %v, want %v", response.ExpiresIn, 600)
	}
	if response.Interval != 5 {
		t.Errorf("Interval = %v, want %v", response.Interval, 5)
	}
}

// TestDeviceCodeResponse_EmptyOptionalField 测试可选字段为空的情况
func TestDeviceCodeResponse_EmptyOptionalField(t *testing.T) {
	response := DeviceCodeResponse{
		DeviceCode:      "device_code_789",
		UserCode:        "user_code_012",
		VerificationURI: "https://example.com/verify",
		ExpiresIn:       300,
		Interval:        10,
		// VerificationURIComplete 为空
	}

	if response.VerificationURIComplete != "" {
		t.Errorf("VerificationURIComplete should be empty, got %v", response.VerificationURIComplete)
	}
}

// TestHttpRequest_Fields 测试 HttpRequest 结构体字段
func TestHttpRequest_Fields(t *testing.T) {
	// 注意：由于 HttpRequest 使用了 enums 包，这里只测试基本字段赋值
	request := HttpRequest{
		URL:     "https://api.example.com/token",
		Headers: map[string]string{"Content-Type": "application/json"},
		Body:    map[string]string{"grant_type": "client_credentials"},
	}

	if request.URL != "https://api.example.com/token" {
		t.Errorf("URL = %v, want %v", request.URL, "https://api.example.com/token")
	}
	if request.Headers["Content-Type"] != "application/json" {
		t.Errorf("Headers[Content-Type] = %v, want %v", request.Headers["Content-Type"], "application/json")
	}
}
