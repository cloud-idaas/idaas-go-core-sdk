package enums

import "testing"

func TestTokenAuthnMethod(t *testing.T) {
	tests := []struct {
		name     string
		method   TokenAuthnMethod
		expected string
	}{
		{"ClientSecretPost", TokenAuthnMethodClientSecretPost, "client_secret_post"},
		{"ClientSecretBasic", TokenAuthnMethodClientSecretBasic, "client_secret_basic"},
		{"ClientSecretJwt", TokenAuthnMethodClientSecretJwt, "client_secret_jwt"},
		{"PrivateKeyJwt", TokenAuthnMethodPrivateKeyJwt, "private_key_jwt"},
		{"Pkcs7", TokenAuthnMethodPkcs7, "pkcs7"},
		{"Pca", TokenAuthnMethodPca, "pca"},
		// TokenAuthnMethodPCA 是 v0.1.0 之前的旧名，保留为 Deprecated 别名，值必须与新名一致。
		{"PCA-alias", TokenAuthnMethodPCA, "pca"},
		{"Oidc", TokenAuthnMethodOidc, "oidc"},
		{"Plugin", TokenAuthnMethodPlugin, "plugin"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.method) != tt.expected {
				t.Errorf("Expected %s to be '%s', got '%s'", tt.name, tt.expected, tt.method)
			}
		})
	}
}

func TestStaleValueBehavior(t *testing.T) {
	tests := []struct {
		name     string
		behavior StaleValueBehavior
		expected string
	}{
		{"Block", StaleValueBehaviorBlock, "BLOCK"},
		{"Allow", StaleValueBehaviorAllow, "ALLOW"},
		{"Refresh", StaleValueBehaviorRefresh, "REFRESH"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.behavior) != tt.expected {
				t.Errorf("Expected %s to be '%s', got '%s'", tt.name, tt.expected, tt.behavior)
			}
		})
	}
}

func TestAuthenticationIdentityEnum(t *testing.T) {
	if AuthenticationIdentityClient != "CLIENT" {
		t.Errorf("Expected AuthenticationIdentityClient to be 'CLIENT', got %s", AuthenticationIdentityClient)
	}

	if AuthenticationIdentityHuman != "HUMAN" {
		t.Errorf("Expected AuthenticationIdentityHuman to be 'HUMAN', got %s", AuthenticationIdentityHuman)
	}
}

func TestClientDeployEnvironmentEnum(t *testing.T) {
	tests := []struct {
		name     string
		env      ClientDeployEnvironmentEnum
		expected string
	}{
		{"Common", ClientDeployEnvironmentCommon, "COMMON"},
		{"Computer", ClientDeployEnvironmentComputer, "COMPUTER"},
		{"Kubernetes", ClientDeployEnvironmentKubernetes, "KUBERNETES"},
		{"AlibabaCloudEcs", ClientDeployEnvironmentAlibabaCloudEcs, "ALIBABA_CLOUD_ECS"},
		{"AlibabaCloudEci", ClientDeployEnvironmentAlibabaCloudEci, "ALIBABA_CLOUD_ECI"},
		{"AlibabaCloudAck", ClientDeployEnvironmentAlibabaCloudAck, "ALIBABA_CLOUD_ACK"},
		{"AwsEc2", ClientDeployEnvironmentAwsEc2, "AWS_EC2"},
		{"AwsEks", ClientDeployEnvironmentAwsEks, "AWS_EKS"},
		{"GoogleVm", ClientDeployEnvironmentGoogleVm, "GOOGLE_VM"},
		{"HuaweiCloudEcs", ClientDeployEnvironmentHuaweiCloudEcs, "HUAWEI_CLOUD_ECS"},
		{"AzureVm", ClientDeployEnvironmentAzureVm, "AZURE_VM"},
		{"Custom", ClientDeployEnvironmentCustom, "CUSTOM"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.env) != tt.expected {
				t.Errorf("Expected %s to be '%s', got '%s'", tt.name, tt.expected, tt.env)
			}
		})
	}
}

func TestContentType(t *testing.T) {
	tests := []struct {
		name     string
		ct       ContentType
		expected string
	}{
		{"Form", ContentTypeForm, "FORM"},
		{"Json", ContentTypeJson, "JSON"},
		{"Xml", ContentTypeXml, "XML"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.ct) != tt.expected {
				t.Errorf("Expected %s to be '%s', got '%s'", tt.name, tt.expected, tt.ct)
			}
		})
	}
}

func TestHttpMethod(t *testing.T) {
	tests := []struct {
		name     string
		method   HttpMethod
		expected string
	}{
		{"Get", HttpMethodGet, "GET"},
		{"Post", HttpMethodPost, "POST"},
		{"Put", HttpMethodPut, "PUT"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.method) != tt.expected {
				t.Errorf("Expected %s to be '%s', got '%s'", tt.name, tt.expected, tt.method)
			}
		})
	}
}

func TestTokenState(t *testing.T) {
	tests := []struct {
		name     string
		state    TokenState
		expected string
	}{
		{"Unknown", TokenStateUnknown, "UNKNOWN"},
		{"Healthy", TokenStateHealthy, "HEALTHY"},
		{"Expiring", TokenStateExpiring, "EXPIRING"},
		{"Expired", TokenStateExpired, "EXPIRED"},
		{"Refreshing", TokenStateRefreshing, "REFRESHING"},
		{"Degraded", TokenStateDegraded, "DEGRADED"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.state) != tt.expected {
				t.Errorf("Expected %s to be '%s', got '%s'", tt.name, tt.expected, tt.state)
			}
		})
	}
}

func TestFailureMode(t *testing.T) {
	tests := []struct {
		name     string
		mode     FailureMode
		expected string
	}{
		{"FailFast", FailureModeFailFast, "FAIL_FAST"},
		{"FailOpen", FailureModeFailOpen, "FAIL_OPEN"},
		{"FailClosed", FailureModeFailClosed, "FAIL_CLOSED"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.mode) != tt.expected {
				t.Errorf("Expected %s to be '%s', got '%s'", tt.name, tt.expected, tt.mode)
			}
		})
	}
}
