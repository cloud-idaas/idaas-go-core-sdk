package errors

// ConfigError 配置错误 (extends ClientError)
type ConfigError struct {
	ClientError
}

// NewConfigError 创建 ConfigError
func NewConfigError(code, message string, cause error) *ConfigError {
	return &ConfigError{
		ClientError: ClientError{
			Code:    code,
			Message: message,
			Cause:   cause,
		},
	}
}
