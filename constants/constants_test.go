package constants

import "testing"

func TestErrorCodeConstants(t *testing.T) {
	// 测试配置类错误码
	if IDaaSCredentialProviderFactoryNotInit != "IDaaSCredentialProviderFactoryNotInit" {
		t.Errorf("Expected IDaaSCredentialProviderFactoryNotInit to be 'IDaaSCredentialProviderFactoryNotInit', got %s", IDaaSCredentialProviderFactoryNotInit)
	}

	if ClientIdNotFound != "ClientIdNotFound" {
		t.Errorf("Expected ClientIdNotFound to be 'ClientIdNotFound', got %s", ClientIdNotFound)
	}

	// 测试认证材料类错误码
	if ClientSecretEnvVarNameNotFound != "ClientSecretEnvVarNameNotFound" {
		t.Errorf("Expected ClientSecretEnvVarNameNotFound to be 'ClientSecretEnvVarNameNotFound', got %s", ClientSecretEnvVarNameNotFound)
	}

	// 测试HTTP类错误码
	if ConnectTimeoutNotValid != "ConnectTimeoutNotValid" {
		t.Errorf("Expected ConnectTimeoutNotValid to be 'ConnectTimeoutNotValid', got %s", ConnectTimeoutNotValid)
	}

	// 测试运行时类错误码
	if InvalidScope != "InvalidScope" {
		t.Errorf("Expected InvalidScope to be 'InvalidScope', got %s", InvalidScope)
	}

	// 测试并发类错误码
	if ConcurrentOperationFailed != "ConcurrentOperationFailed" {
		t.Errorf("Expected ConcurrentOperationFailed to be 'ConcurrentOperationFailed', got %s", ConcurrentOperationFailed)
	}
}

func TestOAuth2ParamsConstants(t *testing.T) {
	if ParamClientID != "client_id" {
		t.Errorf("Expected ParamClientID to be 'client_id', got %s", ParamClientID)
	}

	if ParamGrantType != "grant_type" {
		t.Errorf("Expected ParamGrantType to be 'grant_type', got %s", ParamGrantType)
	}

	if ParamRefreshToken != "refresh_token" {
		t.Errorf("Expected ParamRefreshToken to be 'refresh_token', got %s", ParamRefreshToken)
	}
}

func TestOAuth2GrantTypesConstants(t *testing.T) {
	if GrantTypeClientCredentials != "client_credentials" {
		t.Errorf("Expected GrantTypeClientCredentials to be 'client_credentials', got %s", GrantTypeClientCredentials)
	}

	if GrantTypeRefreshToken != "refresh_token" {
		t.Errorf("Expected GrantTypeRefreshToken to be 'refresh_token', got %s", GrantTypeRefreshToken)
	}

	if GrantTypeDeviceCode != "urn:ietf:params:oauth:grant-type:device_code" {
		t.Errorf("Expected GrantTypeDeviceCode to be correct URN, got %s", GrantTypeDeviceCode)
	}
}

func TestHttpConstants(t *testing.T) {
	if HeaderContentType != "Content-Type" {
		t.Errorf("Expected HeaderContentType to be 'Content-Type', got %s", HeaderContentType)
	}

	if ContentTypeFormUrlEncoded != "application/x-www-form-urlencoded" {
		t.Errorf("Expected ContentTypeFormUrlEncoded to be correct content type, got %s", ContentTypeFormUrlEncoded)
	}

	if ContentTypeJson != "application/json" {
		t.Errorf("Expected ContentTypeJson to be 'application/json', got %s", ContentTypeJson)
	}
}

func TestConfigConstants(t *testing.T) {
	// DefaultConfigPath 是变量，不是常量，所以不能直接比较
	// 这里只测试环境变量名常量
	if EnvVarClientId != "CLOUD_IDAAS_CLIENT_ID" {
		t.Errorf("Expected EnvVarClientId to be 'CLOUD_IDAAS_CLIENT_ID', got %s", EnvVarClientId)
	}

	if EnvVarClientSecret != "CLOUD_IDAAS_CLIENT_SECRET" {
		t.Errorf("Expected EnvVarClientSecret to be 'CLOUD_IDAAS_CLIENT_SECRET', got %s", EnvVarClientSecret)
	}
}

func TestAuthConstants(t *testing.T) {
	if K8sServiceAccountTokenPath != "/var/run/secrets/kubernetes.io/serviceaccount/token" {
		t.Errorf("Expected K8sServiceAccountTokenPath to be correct path, got %s", K8sServiceAccountTokenPath)
	}

	if EcsMetadataUrl != "http://100.100.100.200/latest/api/token" {
		t.Errorf("Expected EcsMetadataUrl to be correct URL, got %s", EcsMetadataUrl)
	}

	if DefaultScope != "openid profile email" {
		t.Errorf("Expected DefaultScope to be 'openid profile email', got %s", DefaultScope)
	}
}
