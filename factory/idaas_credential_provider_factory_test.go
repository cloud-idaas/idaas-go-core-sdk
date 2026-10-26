package factory

import (
	"strings"
	"testing"

	"github.com/cloud-idaas/idaas-go-core-sdk/config"
	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
)

// validTestConfig 构造一个可通过校验的最小配置(client_secret_post + CLIENT 身份)。
func validTestConfig() *config.IDaaSClientConfig {
	return &config.IDaaSClientConfig{
		ClientId:       "test_client_id",
		InstanceId:     "test_instance_id",
		IssuerEndpoint: "https://test.example.com/oauth2",
		TokenEndpoint:  "https://test.example.com/oauth2/token",
		Scope:          "api://test.example.com|read",
		AuthnConfiguration: &config.IdentityAuthenticationConfiguration{
			AuthnMethod:               enums.TokenAuthnMethodClientSecretPost,
			IdentityType:              enums.AuthenticationIdentityClient,
			ClientSecretEnvVarName:    "CLOUD_IDAAS_CLIENT_SECRET",
			HumanAuthenticateClientId: "iap_developer",
		},
	}
}

// TestFactory_IdempotentInit 验证幂等 init :
// 已初始化时再次 Initialize 应返回 nil,不重建 provider 缓存。
func TestFactory_IdempotentInit(t *testing.T) {
	Reset()
	defer Reset()

	f := GetInstance()
	cfg := validTestConfig()

	if err := f.Initialize(cfg); err != nil {
		t.Fatalf("first Initialize failed: %v", err)
	}

	// 第二次 Initialize 应返回 nil(幂等)
	if err := f.Initialize(cfg); err != nil {
		t.Fatalf("second Initialize should be idempotent, got: %v", err)
	}

	if !f.IsInitialized() {
		t.Error("factory should be initialized after Initialize")
	}
}

// TestFactory_Reset 验证 Reset 清除状态后可重新初始化。
func TestFactory_Reset(t *testing.T) {
	Reset()
	defer Reset()

	f := GetInstance()
	cfg := validTestConfig()

	if err := f.Initialize(cfg); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	if !f.IsInitialized() {
		t.Error("should be initialized")
	}

	f.Reset()
	if f.IsInitialized() {
		t.Error("should not be initialized after Reset")
	}

	// 重新初始化应成功
	if err := f.Initialize(cfg); err != nil {
		t.Fatalf("re-initialize after Reset failed: %v", err)
	}
}

// TestFactory_NotInitializedReturnsError 验证未初始化时获取 provider 返回错误。
func TestFactory_NotInitializedReturnsError(t *testing.T) {
	Reset()
	defer Reset()

	f := GetInstance()
	_, err := f.GetIDaaSCredentialProviderByScope("test")
	if err == nil {
		t.Error("expected error when factory not initialized")
	}
}

// TestFactory_BuildCacheKey 验证缓存键带身份维度 :
// 同一 scope 下 CLIENT 和 HUMAN 的缓存键不同。
func TestFactory_BuildCacheKey(t *testing.T) {
	Reset()
	defer Reset()

	f := GetInstance()
	cfg := validTestConfig()
	if err := f.Initialize(cfg); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	clientKey := f.buildCacheKey(enums.AuthenticationIdentityClient, "api://test|read", "credential")
	humanKey := f.buildCacheKey(enums.AuthenticationIdentityHuman, "api://test|read", "credential")

	if clientKey == humanKey {
		t.Error("CLIENT and HUMAN should have different cache keys")
	}

	// credential 和 exchange 的 key 也应不同
	exchangeKey := f.buildCacheKey(enums.AuthenticationIdentityClient, "api://test|read", "exchange")
	if clientKey == exchangeKey {
		t.Error("credential and exchange should have different cache keys")
	}
}

// TestFactory_BuildCacheKey_HumanUsesHumanClientId 验证 HUMAN 身份的缓存键
// 使用 HumanAuthenticateClientId 而非 ClientId。
func TestFactory_BuildCacheKey_HumanUsesHumanClientId(t *testing.T) {
	Reset()
	defer Reset()

	f := GetInstance()
	cfg := validTestConfig()
	cfg.AuthnConfiguration.HumanAuthenticateClientId = "custom_human_client_id"
	if err := f.Initialize(cfg); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	humanKey := f.buildCacheKey(enums.AuthenticationIdentityHuman, "scope", "credential")
	// HumanAuthenticateClientId = "custom_human_client_id" 应出现在键中
	if !strings.Contains(humanKey, "custom_human_client_id") {
		t.Errorf("HUMAN cache key should contain HumanAuthenticateClientId, got: %s", humanKey)
	}

	// CLIENT 身份的键应使用 ClientId 而非 HumanAuthenticateClientId
	clientKey := f.buildCacheKey(enums.AuthenticationIdentityClient, "scope", "credential")
	if !strings.Contains(clientKey, "test_client_id") {
		t.Errorf("CLIENT cache key should contain ClientId, got: %s", clientKey)
	}
	if strings.Contains(clientKey, "custom_human_client_id") {
		t.Errorf("CLIENT cache key should NOT contain HumanAuthenticateClientId, got: %s", clientKey)
	}
}

// TestFactory_GetConfig_AfterInit 验证 GetConfig 返回已冻结的配置快照。
func TestFactory_GetConfig_AfterInit(t *testing.T) {
	Reset()
	defer Reset()

	f := GetInstance()
	cfg := validTestConfig()
	if err := f.Initialize(cfg); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	got := f.GetConfig()
	if got == nil {
		t.Fatal("GetConfig should not return nil after init")
	}
	if got.ClientId != "test_client_id" {
		t.Errorf("GetConfig().ClientId = %s, want test_client_id", got.ClientId)
	}
}

// TestFactory_GetIDaaSInstanceId 验证 GetIDaaSInstanceId 包级函数。
func TestFactory_GetIDaaSInstanceId(t *testing.T) {
	Reset()
	defer Reset()

	cfg := validTestConfig()
	if err := InitWithConfig(cfg); err != nil {
		t.Fatalf("InitWithConfig failed: %v", err)
	}
	if got := GetIDaaSInstanceId(); got != "test_instance_id" {
		t.Errorf("GetIDaaSInstanceId = %s, want test_instance_id", got)
	}
}

// TestFactory_GetClientId 验证 GetClientId 包级函数。
func TestFactory_GetClientId(t *testing.T) {
	Reset()
	defer Reset()

	cfg := validTestConfig()
	if err := InitWithConfig(cfg); err != nil {
		t.Fatalf("InitWithConfig failed: %v", err)
	}
	if got := GetClientId(); got != "test_client_id" {
		t.Errorf("GetClientId = %s, want test_client_id", got)
	}
}

// TestFactory_GetEndpoints 验证 GetDeveloperApiEndpoint / GetOpenApiEndpoint。
func TestFactory_GetEndpoints(t *testing.T) {
	Reset()
	defer Reset()

	cfg := validTestConfig()
	cfg.DeveloperApiEndpoint = "https://test.example.com/dev"
	cfg.OpenApiEndpoint = "https://test.example.com/openapi"
	if err := InitWithConfig(cfg); err != nil {
		t.Fatalf("InitWithConfig failed: %v", err)
	}

	if got := GetDeveloperApiEndpoint(); got != "https://test.example.com/dev" {
		t.Errorf("GetDeveloperApiEndpoint = %s, want https://test.example.com/dev", got)
	}
	if got := GetOpenApiEndpoint(); got != "https://test.example.com/openapi" {
		t.Errorf("GetOpenApiEndpoint = %s, want https://test.example.com/openapi", got)
	}
}

// TestFactory_GetHttpConfig 验证 GetHttpConfig 返回深拷贝。
func TestFactory_GetHttpConfig(t *testing.T) {
	Reset()
	defer Reset()

	cfg := validTestConfig()
	cfg.HttpConfiguration = &config.HttpConfiguration{
		ConnectTimeout: 5000,
		ReadTimeout:    10000,
	}
	if err := InitWithConfig(cfg); err != nil {
		t.Fatalf("InitWithConfig failed: %v", err)
	}

	hc := GetHttpConfig()
	if hc == nil {
		t.Fatal("GetHttpConfig should not return nil")
	}
	if hc.ConnectTimeout != 5000 {
		t.Errorf("ConnectTimeout = %d, want 5000", hc.ConnectTimeout)
	}

	// 深拷贝语义:修改返回值不应影响内部状态。
	hc.ConnectTimeout = 9999
	hc2 := GetHttpConfig()
	if hc2.ConnectTimeout != 5000 {
		t.Errorf("deep copy failed: internal state changed to %d", hc2.ConnectTimeout)
	}
}

// TestFactory_NormalizeEndpoints 验证 http:// 被提升为 https://。
func TestFactory_NormalizeEndpoints(t *testing.T) {
	Reset()
	defer Reset()

	cfg := &config.IDaaSClientConfig{
		ClientId:       "cid",
		InstanceId:     "iid",
		IssuerEndpoint: "http://test.example.com/oauth2",
		TokenEndpoint:  "http://test.example.com/oauth2/token",
		AuthnConfiguration: &config.IdentityAuthenticationConfiguration{
			AuthnMethod:               enums.TokenAuthnMethodClientSecretPost,
			IdentityType:              enums.AuthenticationIdentityClient,
			ClientSecretEnvVarName:    "CLOUD_IDAAS_CLIENT_SECRET",
			HumanAuthenticateClientId: "iap_developer",
		},
	}

	if err := InitWithConfig(cfg); err != nil {
		t.Fatalf("InitWithConfig with http:// endpoints should succeed (normalized), got: %v", err)
	}

	got := GetInstance().GetConfig()
	if got.IssuerEndpoint != "https://test.example.com/oauth2" {
		t.Errorf("IssuerEndpoint should be normalized to https, got: %s", got.IssuerEndpoint)
	}
	if got.TokenEndpoint != "https://test.example.com/oauth2/token" {
		t.Errorf("TokenEndpoint should be normalized to https, got: %s", got.TokenEndpoint)
	}
}

// TestFactory_NormalizeEndpoints_BareHost 回归 FAIL-1（factory_public_api 集成用例）：
// 官方模板 / README / Java、Python SDK 配置里 openApiEndpoint、developerApiEndpoint
// 按阿里云 POP 端点惯例写裸 host（如 eiam.cn-hangzhou.aliyuncs.com）。
// 修复前 validator 对带 scheme 的强校验把这种形态拒在 factory.Init 之外
// （InvalidEndpointScheme），与 Java NormalizeUtil.convertHttps / Python
// NormalizeUtil._convert_to_https 的"裸 host 自动补 https://"语义不一致。
// 本用例锁定跨 SDK 对齐后的行为：Init 成功且 getter 返回补全后的 https:// 形态。
func TestFactory_NormalizeEndpoints_BareHost(t *testing.T) {
	Reset()
	defer Reset()

	cfg := validTestConfig()
	cfg.OpenApiEndpoint = "eiam.cn-hangzhou.aliyuncs.com"
	cfg.DeveloperApiEndpoint = "eiam-developerapi.cn-hangzhou.aliyuncs.com"

	if err := InitWithConfig(cfg); err != nil {
		t.Fatalf("bare-host endpoints must be accepted (auto https:// prefix, Java/Python parity), got: %v", err)
	}

	if got := GetOpenApiEndpoint(); got != "https://eiam.cn-hangzhou.aliyuncs.com" {
		t.Errorf("GetOpenApiEndpoint = %s, want https://eiam.cn-hangzhou.aliyuncs.com", got)
	}
	if got := GetDeveloperApiEndpoint(); got != "https://eiam-developerapi.cn-hangzhou.aliyuncs.com" {
		t.Errorf("GetDeveloperApiEndpoint = %s, want https://eiam-developerapi.cn-hangzhou.aliyuncs.com", got)
	}
}

// TestFactory_NormalizeEndpoints_HttpsUnchanged 验证已是 https 的端点不被修改。
func TestFactory_NormalizeEndpoints_HttpsUnchanged(t *testing.T) {
	Reset()
	defer Reset()

	cfg := validTestConfig()
	original := cfg.TokenEndpoint
	if err := InitWithConfig(cfg); err != nil {
		t.Fatalf("InitWithConfig failed: %v", err)
	}
	if GetInstance().GetConfig().TokenEndpoint != original {
		t.Error("https endpoint should not be modified by normalization")
	}
}
