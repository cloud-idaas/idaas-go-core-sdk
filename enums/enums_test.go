package enums

import "testing"

func TestTokenAuthnMethod(t *testing.T) {
	tests := []struct {
		name     string
		method   TokenAuthnMethod
		expected string
	}{
		{"None", TokenAuthnMethodNone, "none"},
		{"ClientSecretPost", TokenAuthnMethodClientSecretPost, "client_secret_post"},
		{"ClientSecretBasic", TokenAuthnMethodClientSecretBasic, "client_secret_basic"},
		{"ClientSecretJwt", TokenAuthnMethodClientSecretJwt, "client_secret_jwt"},
		{"PrivateKeyJwt", TokenAuthnMethodPrivateKeyJwt, "private_key_jwt"},
		{"Pkcs7", TokenAuthnMethodPkcs7, "pkcs7"},
		{"PCA", TokenAuthnMethodPCA, "pca"},
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
		{"AwsEsk", ClientDeployEnvironmentAwsEsk, "AWS_ESK"},
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
		{"Raw", ContentTypeRaw, "RAW"},
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
