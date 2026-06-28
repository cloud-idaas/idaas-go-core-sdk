package domain

import "encoding/json"

// ErrResponse 错误响应结构体 (§3.4)
// 支持双格式 JSON 解析：标准 OAuth2 错误格式和 IDaaS 自定义格式
type ErrResponse struct {
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`

	// IDaaS 自定义格式
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

// UnmarshalJSON 自定义 JSON 解析，支持双格式
func (e *ErrResponse) UnmarshalJSON(data []byte) error {
	// 先尝试解析为标准格式
	type standardFormat struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}

	var std standardFormat
	if err := json.Unmarshal(data, &std); err == nil && std.Error != "" {
		e.Error = std.Error
		e.ErrorDescription = std.ErrorDescription
		return nil
	}

	// 再尝试解析为 IDaaS 自定义格式
	type idaasFormat struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}

	var idaas idaasFormat
	if err := json.Unmarshal(data, &idaas); err == nil && idaas.Code != "" {
		e.Code = idaas.Code
		e.Message = idaas.Message
		return nil
	}

	return nil
}

// GetErrorCode 获取错误码
func (e *ErrResponse) GetErrorCode() string {
	if e.Error != "" {
		return e.Error
	}
	return e.Code
}

// GetErrorMessage 获取错误消息
func (e *ErrResponse) GetErrorMessage() string {
	if e.ErrorDescription != "" {
		return e.ErrorDescription
	}
	return e.Message
}
