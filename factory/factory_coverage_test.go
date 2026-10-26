package factory

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cloud-idaas/idaas-go-core-sdk/constants"
	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
	"github.com/cloud-idaas/idaas-go-core-sdk/errors"
	"github.com/cloud-idaas/idaas-go-core-sdk/provider"
)

// TestInit_FromSinglePath 验证从单个配置文件路径初始化
func TestInit_FromSinglePath(t *testing.T) {
	Reset()
	defer Reset()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")

	// Set env var for client secret (needed by provider creation)
	os.Setenv("CLOUD_IDAAS_CLIENT_SECRET", "test_secret")
	defer os.Unsetenv("CLOUD_IDAAS_CLIENT_SECRET")

	cfgJSON := `{
		"clientId": "init_cid",
		"idaasInstanceId": "init_iid",
		"issuer": "https://init.example.com/oauth2",
		"tokenEndpoint": "https://init.example.com/oauth2/token",
		"scope": "api://init|read",
		"authnConfiguration": {
			"authnMethod": "client_secret_post",
			"identityType": "CLIENT",
			"clientSecretEnvVarName": "CLOUD_IDAAS_CLIENT_SECRET"
		}
	}`
	if err := os.WriteFile(cfgPath, []byte(cfgJSON), 0o644); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	if err := Init(cfgPath); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	if !GetInstance().IsInitialized() {
		t.Error("factory should be initialized after Init")
	}
	if got := GetClientId(); got != "init_cid" {
		t.Errorf("ClientId = %q, want %q", got, "init_cid")
	}
}

// TestInit_NoPaths_FailsHard 验证无路径且无配置文件时返回错误
func TestInit_NoPaths_FailsHard(t *testing.T) {
	Reset()
	defer Reset()

	os.Unsetenv("CLOUD_IDAAS_CONFIG_PATH")
	// 隔离默认配置路径：开发机上 ~/.cloud_idaas/client-config.json 可能真实存在
	// （本机即如此），不隔离时 Init 会加载它、用例假阴性。
	restore := constants.DefaultConfigPath
	constants.DefaultConfigPath = filepath.Join(t.TempDir(), "definitely-missing-client-config.json")
	defer func() { constants.DefaultConfigPath = restore }()

	err := Init()
	if err == nil {
		t.Fatal("expected error when no config source available")
	}
}

// TestInit_MultiplePaths_FirstSucceeds 验证多路径时第一个成功加载生效
func TestInit_MultiplePaths_FirstSucceeds(t *testing.T) {
	Reset()
	defer Reset()

	os.Setenv("CLOUD_IDAAS_CLIENT_SECRET", "test_secret")
	defer os.Unsetenv("CLOUD_IDAAS_CLIENT_SECRET")

	dir := t.TempDir()
	goodPath := filepath.Join(dir, "good.json")

	cfgJSON := `{
		"clientId": "multi_cid",
		"idaasInstanceId": "multi_iid",
		"issuer": "https://multi.example.com/oauth2",
		"tokenEndpoint": "https://multi.example.com/oauth2/token",
		"authnConfiguration": {
			"authnMethod": "client_secret_post",
			"identityType": "CLIENT",
			"clientSecretEnvVarName": "CLOUD_IDAAS_CLIENT_SECRET"
		}
	}`
	if err := os.WriteFile(goodPath, []byte(cfgJSON), 0o644); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	// First path doesn't exist, second does
	if err := Init("/nonexistent/path.json", goodPath); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	if got := GetClientId(); got != "multi_cid" {
		t.Errorf("ClientId = %q, want %q", got, "multi_cid")
	}
}

// TestInit_Idempotent 验证已初始化时再次 Init 返回 nil
func TestInit_Idempotent(t *testing.T) {
	Reset()
	defer Reset()

	cfg := validTestConfig()
	if err := InitWithConfig(cfg); err != nil {
		t.Fatalf("first InitWithConfig failed: %v", err)
	}
	// Second init should be idempotent (return nil)
	if err := InitWithConfig(cfg); err != nil {
		t.Fatalf("second InitWithConfig should be idempotent, got: %v", err)
	}
}

// TestGetIDaaSCredentialProvider_NotInitialized 验证未初始化时返回错误
func TestGetIDaaSCredentialProvider_NotInitialized(t *testing.T) {
	Reset()
	defer Reset()

	_, err := GetIDaaSCredentialProvider()
	if err == nil {
		t.Fatal("expected error when factory not initialized")
	}
}

// TestGetIDaaSCredentialProvider_Initialized 验证初始化后可获取 provider
func TestGetIDaaSCredentialProvider_Initialized(t *testing.T) {
	Reset()
	defer Reset()

	os.Setenv("CLOUD_IDAAS_CLIENT_SECRET", "test_secret")
	defer os.Unsetenv("CLOUD_IDAAS_CLIENT_SECRET")

	cfg := validTestConfig()
	if err := InitWithConfig(cfg); err != nil {
		t.Fatalf("InitWithConfig failed: %v", err)
	}

	prov, err := GetIDaaSCredentialProvider()
	if err != nil {
		t.Fatalf("GetIDaaSCredentialProvider failed: %v", err)
	}
	if prov == nil {
		t.Fatal("expected non-nil provider")
	}
}

// TestGetIDaaSCredentialProviderByScope_PackageFunc 验证包级函数
func TestGetIDaaSCredentialProviderByScope_PackageFunc(t *testing.T) {
	Reset()
	defer Reset()

	os.Setenv("CLOUD_IDAAS_CLIENT_SECRET", "test_secret")
	defer os.Unsetenv("CLOUD_IDAAS_CLIENT_SECRET")

	cfg := validTestConfig()
	if err := InitWithConfig(cfg); err != nil {
		t.Fatalf("InitWithConfig failed: %v", err)
	}

	prov, err := GetIDaaSCredentialProviderByScope("api://test.example.com|read")
	if err != nil {
		t.Fatalf("GetIDaaSCredentialProviderByScope failed: %v", err)
	}
	if prov == nil {
		t.Fatal("expected non-nil provider")
	}
}

// TestGetIDaaSTokenExchangeCredentialProvider_NotInitialized 验证未初始化时返回错误
func TestGetIDaaSTokenExchangeCredentialProvider_NotInitialized(t *testing.T) {
	Reset()
	defer Reset()

	_, err := GetIDaaSTokenExchangeCredentialProvider()
	if err == nil {
		t.Fatal("expected error when factory not initialized")
	}
}

// TestGetIDaaSTokenExchangeCredentialProvider_Success 验证成功获取
func TestGetIDaaSTokenExchangeCredentialProvider_Success(t *testing.T) {
	Reset()
	defer Reset()

	os.Setenv("CLOUD_IDAAS_CLIENT_SECRET", "exchange_secret")
	defer os.Unsetenv("CLOUD_IDAAS_CLIENT_SECRET")

	cfg := validTestConfig()
	if err := InitWithConfig(cfg); err != nil {
		t.Fatalf("InitWithConfig failed: %v", err)
	}

	prov, err := GetIDaaSTokenExchangeCredentialProvider()
	if err != nil {
		t.Fatalf("GetIDaaSTokenExchangeCredentialProvider failed: %v", err)
	}
	if prov == nil {
		t.Fatal("expected non-nil exchange provider")
	}
}

// TestGetIDaaSTokenExchangeCredentialProviderByScope_PackageFunc 验证包级函数
func TestGetIDaaSTokenExchangeCredentialProviderByScope_PackageFunc(t *testing.T) {
	Reset()
	defer Reset()

	os.Setenv("CLOUD_IDAAS_CLIENT_SECRET", "exchange_secret")
	defer os.Unsetenv("CLOUD_IDAAS_CLIENT_SECRET")

	cfg := validTestConfig()
	if err := InitWithConfig(cfg); err != nil {
		t.Fatalf("InitWithConfig failed: %v", err)
	}

	prov, err := GetIDaaSTokenExchangeCredentialProviderByScope("api://test|read")
	if err != nil {
		t.Fatalf("GetIDaaSTokenExchangeCredentialProviderByScope failed: %v", err)
	}
	if prov == nil {
		t.Fatal("expected non-nil exchange provider")
	}
}

// TestGetIDaaSTokenExchangeCredentialProviderByScope_NotInitialized 验证未初始化时返回错误
func TestGetIDaaSTokenExchangeCredentialProviderByScope_NotInitialized(t *testing.T) {
	Reset()
	defer Reset()

	_, err := GetIDaaSTokenExchangeCredentialProviderByScope("test")
	if err == nil {
		t.Fatal("expected error when factory not initialized")
	}
}

// TestCreateCredentialProvider_Success 验证已废弃方法仍可工作
func TestCreateCredentialProvider_Success(t *testing.T) {
	Reset()
	defer Reset()

	os.Setenv("CLOUD_IDAAS_CLIENT_SECRET", "test_secret")
	defer os.Unsetenv("CLOUD_IDAAS_CLIENT_SECRET")

	cfg := validTestConfig()
	f := GetInstance()
	if err := f.Initialize(cfg); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	prov, err := f.CreateCredentialProvider()
	if err != nil {
		t.Fatalf("CreateCredentialProvider failed: %v", err)
	}
	if prov == nil {
		t.Fatal("expected non-nil provider")
	}
}

// TestCreateHumanProvider_Success 验证创建人类凭证提供者
func TestCreateHumanProvider_Success(t *testing.T) {
	Reset()
	defer Reset()

	cfg := validTestConfig()
	cfg.AuthnConfiguration.IdentityType = enums.AuthenticationIdentityHuman
	cfg.DeviceAuthorizationEndpoint = "https://example.com/device_auth"
	f := GetInstance()
	if err := f.Initialize(cfg); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// createHumanProvider is an internal method; we can call it directly since we're in the same package
	prov, err := f.createHumanProvider(cfg, "", f.httpClient, f.baseCtx, f.userCodeHandler)
	if err != nil {
		t.Fatalf("createHumanProvider failed: %v", err)
	}
	if prov == nil {
		t.Fatal("expected non-nil human provider")
	}
}

// TestCreateHumanProvider_MissingDeviceAuthEndpoint 验证 HUMAN 缺少 device authorization endpoint
// 时在 Initialize 阶段即失败（预热失败只打 WARN，不能依赖它暴露配置错误）；
// createHumanProvider 自身的防御性检查仍保留。
func TestCreateHumanProvider_MissingDeviceAuthEndpoint(t *testing.T) {
	Reset()
	defer Reset()

	cfg := validTestConfig()
	cfg.AuthnConfiguration.IdentityType = enums.AuthenticationIdentityHuman
	cfg.DeviceAuthorizationEndpoint = ""
	f := GetInstance()
	if err := f.Initialize(cfg); !errors.HasCode(err, constants.DeviceAuthorizationEndpointNotFound) {
		t.Fatalf("expected DeviceAuthorizationEndpointNotFound from Initialize, got %v", err)
	}

	cfg.DeviceAuthorizationEndpoint = "https://example.com/device_auth"
	if err := f.Initialize(cfg); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	broken := *cfg
	broken.DeviceAuthorizationEndpoint = ""
	if _, err := f.createHumanProvider(&broken, "", f.httpClient, f.baseCtx, f.userCodeHandler); err == nil {
		t.Fatal("expected error when DeviceAuthorizationEndpoint is missing")
	}
}

// TestInitialize_HumanWithoutAuthnMethod 验证场景 13：HUMAN 不设 authnMethod 可完成初始化
// 并取到 HUMAN provider（与 Java/Python 对齐）。
func TestInitialize_HumanWithoutAuthnMethod(t *testing.T) {
	Reset()
	defer Reset()

	cfg := validTestConfig()
	cfg.AuthnConfiguration.IdentityType = enums.AuthenticationIdentityHuman
	cfg.AuthnConfiguration.AuthnMethod = ""
	cfg.AuthnConfiguration.ClientSecretEnvVarName = ""
	cfg.AuthnConfiguration.HumanAuthenticateClientId = ""
	cfg.DeviceAuthorizationEndpoint = "https://example.com/device_auth"
	if err := InitWithConfig(cfg); err != nil {
		t.Fatalf("HUMAN config without authnMethod should initialize, got: %v", err)
	}

	p, err := GetIDaaSCredentialProviderByScope(cfg.Scope)
	if err != nil {
		t.Fatalf("GetIDaaSCredentialProviderByScope failed: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil human provider")
	}
}

// TestInitialize_ClientWithoutAuthnMethod 回归：CLIENT 不设 authnMethod 仍在 Initialize 阶段失败。
func TestInitialize_ClientWithoutAuthnMethod(t *testing.T) {
	Reset()
	defer Reset()

	cfg := validTestConfig()
	cfg.AuthnConfiguration.AuthnMethod = ""
	if err := InitWithConfig(cfg); !errors.HasCode(err, constants.AuthnConfigurationNotFound) {
		t.Fatalf("expected AuthnConfigurationNotFound, got %v", err)
	}
}

// TestInitialize_EmptyIdentityTypeDefaultsToClient 回归：identityType 留空时按 CLIENT 处理（与 Java 默认值一致），
// 而不是通过校验后在获取 provider 时报 UnsupportedIdentityType。
func TestInitialize_EmptyIdentityTypeDefaultsToClient(t *testing.T) {
	Reset()
	defer Reset()

	cfg := validTestConfig()
	cfg.AuthnConfiguration.IdentityType = ""
	if err := InitWithConfig(cfg); err != nil {
		t.Fatalf("InitWithConfig failed: %v", err)
	}
	if got := GetInstance().GetConfig().AuthnConfiguration.IdentityType; got != enums.AuthenticationIdentityClient {
		t.Fatalf("identityType = %q, want CLIENT", got)
	}
	// Defaulting 作用于工厂内部副本，不修改调用方的 cfg。
	if cfg.AuthnConfiguration.IdentityType != "" {
		t.Fatalf("caller cfg mutated: identityType = %q", cfg.AuthnConfiguration.IdentityType)
	}
	if _, err := GetIDaaSCredentialProviderByScope(cfg.Scope); err != nil {
		t.Fatalf("GetIDaaSCredentialProviderByScope failed: %v", err)
	}
}

// TestTokenExchange_HumanWithoutAuthnMethod HUMAN 不设 authnMethod 时，token exchange 在获取阶段即报错。
func TestTokenExchange_HumanWithoutAuthnMethod(t *testing.T) {
	Reset()
	defer Reset()

	cfg := validTestConfig()
	cfg.AuthnConfiguration.IdentityType = enums.AuthenticationIdentityHuman
	cfg.AuthnConfiguration.AuthnMethod = ""
	cfg.AuthnConfiguration.ClientSecretEnvVarName = ""
	cfg.DeviceAuthorizationEndpoint = "https://example.com/device_auth"
	if err := InitWithConfig(cfg); err != nil {
		t.Fatalf("InitWithConfig failed: %v", err)
	}

	_, err := GetIDaaSTokenExchangeCredentialProviderByScope(cfg.Scope)
	if !errors.HasCode(err, constants.AuthnConfigurationNotFound) {
		t.Fatalf("expected AuthnConfigurationNotFound, got %v", err)
	}
}

// TestCreateTokenExchangeProviderByScope_Success 验证成功创建 token exchange provider
func TestCreateTokenExchangeProviderByScope_Success(t *testing.T) {
	Reset()
	defer Reset()

	os.Setenv("CLOUD_IDAAS_CLIENT_SECRET", "exchange_secret")
	defer os.Unsetenv("CLOUD_IDAAS_CLIENT_SECRET")

	cfg := validTestConfig()
	f := GetInstance()
	if err := f.Initialize(cfg); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	prov, err := f.createTokenExchangeProviderByScope("api://test|read")
	if err != nil {
		t.Fatalf("createTokenExchangeProviderByScope failed: %v", err)
	}
	if prov == nil {
		t.Fatal("expected non-nil exchange provider")
	}
}

// TestCreateTokenExchangeProviderByScope_NotInitialized 验证未初始化时返回错误
func TestCreateTokenExchangeProviderByScope_NotInitialized(t *testing.T) {
	Reset()
	defer Reset()

	f := GetInstance()
	_, err := f.createTokenExchangeProviderByScope("test")
	if err == nil {
		t.Fatal("expected error when factory not initialized")
	}
}

// TestCreateTokenExchangeProviderByScope_PluginNotSupported 验证 PLUGIN 方式不支持 token exchange
func TestCreateTokenExchangeProviderByScope_PluginNotSupported(t *testing.T) {
	Reset()
	defer Reset()

	cfg := validTestConfig()
	cfg.AuthnConfiguration.AuthnMethod = enums.TokenAuthnMethodPlugin
	cfg.AuthnConfiguration.PluginName = "testPlugin"
	cfg.OpenApiEndpoint = "https://example.com/api"
	f := GetInstance()
	if err := f.Initialize(cfg); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	_, err := f.createTokenExchangeProviderByScope("test")
	if !errors.HasCode(err, constants.UnsupportedAuthenticationMethod) {
		t.Fatalf("expected UnsupportedAuthenticationMethod for PLUGIN token exchange, got %v", err)
	}
}

// TestCreateTokenExchangeProviderByScope_MissingClientSecret 验证缺少 client secret 时
// ExchangeToken 返回 ClientSecretNotFound。secret 按请求读取，创建 provider 时不检查。
func TestCreateTokenExchangeProviderByScope_MissingClientSecret(t *testing.T) {
	Reset()
	defer Reset()

	// Don't set the env var
	os.Unsetenv("CLOUD_IDAAS_CLIENT_SECRET")

	cfg := validTestConfig()
	f := GetInstance()
	if err := f.Initialize(cfg); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	p, err := f.createTokenExchangeProviderByScope("test")
	if err != nil {
		t.Fatalf("createTokenExchangeProviderByScope failed: %v", err)
	}
	_, err = p.ExchangeToken(provider.TokenExchangeRequest{SubjectToken: "subject-at"})
	if !errors.HasCode(err, constants.ClientSecretNotFound) {
		t.Fatalf("expected ClientSecretNotFound, got %v", err)
	}
}

// TestCreateTokenExchangeProviderByScope_PrivateKeyJwtSupported 验证 private_key_jwt 可创建
// token exchange provider (与 Java 一致；PLUGIN 仍被拒绝，见上方用例)。
func TestCreateTokenExchangeProviderByScope_PrivateKeyJwtSupported(t *testing.T) {
	Reset()
	defer Reset()

	cfg := validTestConfig()
	cfg.AuthnConfiguration.AuthnMethod = enums.TokenAuthnMethodPrivateKeyJwt
	cfg.AuthnConfiguration.PrivateKeyEnvVarName = "CLOUD_IDAAS_PRIVATE_KEY"
	f := GetInstance()
	if err := f.Initialize(cfg); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	if _, err := f.createTokenExchangeProviderByScope("test"); err != nil {
		t.Fatalf("private_key_jwt token exchange provider should be created: %v", err)
	}
}

// TestCreateTokenExchangeProviderByScope_Caching 验证相同 scope 返回缓存的 provider
func TestCreateTokenExchangeProviderByScope_Caching(t *testing.T) {
	Reset()
	defer Reset()

	os.Setenv("CLOUD_IDAAS_CLIENT_SECRET", "exchange_secret")
	defer os.Unsetenv("CLOUD_IDAAS_CLIENT_SECRET")

	cfg := validTestConfig()
	f := GetInstance()
	if err := f.Initialize(cfg); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	p1, err := f.createTokenExchangeProviderByScope("api://test|read")
	if err != nil {
		t.Fatalf("first createTokenExchangeProviderByScope failed: %v", err)
	}
	p2, err := f.createTokenExchangeProviderByScope("api://test|read")
	if err != nil {
		t.Fatalf("second createTokenExchangeProviderByScope failed: %v", err)
	}
	if p1 != p2 {
		t.Error("same scope should return cached provider instance")
	}
}

// TestFactory_GetIDaaSTokenExchangeCredentialProviderByScope_Success 验证方法级别调用
func TestFactory_GetIDaaSTokenExchangeCredentialProviderByScope_Success(t *testing.T) {
	Reset()
	defer Reset()

	os.Setenv("CLOUD_IDAAS_CLIENT_SECRET", "exchange_secret")
	defer os.Unsetenv("CLOUD_IDAAS_CLIENT_SECRET")

	cfg := validTestConfig()
	f := GetInstance()
	if err := f.Initialize(cfg); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	prov, err := f.GetIDaaSTokenExchangeCredentialProviderByScope("api://test|read")
	if err != nil {
		t.Fatalf("GetIDaaSTokenExchangeCredentialProviderByScope failed: %v", err)
	}
	if prov == nil {
		t.Fatal("expected non-nil exchange provider")
	}
}

// waitForListenerCalls waits a short time for async goroutines to complete
func waitForListenerCalls(t *testing.T, l *recordingListener, targetCount int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		l.mu.Lock()
		if l.refreshedCount+l.refreshFailedCount+l.degradationEnteredCount+l.degradationExitedCount >= targetCount {
			l.mu.Unlock()
			return
		}
		l.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
}

// TestNotifyTokenRefreshed 验证刷新成功通知
func TestNotifyTokenRefreshed(t *testing.T) {
	f := &IDaaSCredentialProviderFactory{}
	l := &recordingListener{}
	f.AddTokenListener(l)

	expiresAt := time.Now().Add(1 * time.Hour)
	f.notifyTokenRefreshed(expiresAt, "api://test|read")

	waitForListenerCalls(t, l, 1, 500*time.Millisecond)

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.refreshedCount != 1 {
		t.Errorf("refreshedCount = %d, want 1", l.refreshedCount)
	}
	if l.lastScope != "api://test|read" {
		t.Errorf("lastScope = %q, want %q", l.lastScope, "api://test|read")
	}
}

// TestNotifyTokenRefreshFailed 验证刷新失败通知
func TestNotifyTokenRefreshFailed(t *testing.T) {
	f := &IDaaSCredentialProviderFactory{}
	l := &recordingListener{}
	f.AddTokenListener(l)

	f.notifyTokenRefreshFailed(errMock("refresh failed"), true)

	waitForListenerCalls(t, l, 1, 500*time.Millisecond)

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.refreshFailedCount != 1 {
		t.Errorf("refreshFailedCount = %d, want 1", l.refreshFailedCount)
	}
	if !l.lastWillRetry {
		t.Error("lastWillRetry = false, want true")
	}
}

// TestNotifyDegradationEntered 验证进入降级通知
func TestNotifyDegradationEntered(t *testing.T) {
	f := &IDaaSCredentialProviderFactory{}
	l := &recordingListener{}
	f.AddTokenListener(l)

	f.notifyDegradationEntered(3)

	waitForListenerCalls(t, l, 1, 500*time.Millisecond)

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.degradationEnteredCount != 1 {
		t.Errorf("degradationEnteredCount = %d, want 1", l.degradationEnteredCount)
	}
	if l.lastConsecutiveFailures != 3 {
		t.Errorf("lastConsecutiveFailures = %d, want 3", l.lastConsecutiveFailures)
	}
}

// TestNotifyDegradationExited 验证退出降级通知
func TestNotifyDegradationExited(t *testing.T) {
	f := &IDaaSCredentialProviderFactory{}
	l := &recordingListener{}
	f.AddTokenListener(l)

	f.notifyDegradationExited(enums.TokenStateHealthy)

	waitForListenerCalls(t, l, 1, 500*time.Millisecond)

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.degradationExitedCount != 1 {
		t.Errorf("degradationExitedCount = %d, want 1", l.degradationExitedCount)
	}
	if l.lastExitedState != enums.TokenStateHealthy {
		t.Errorf("lastExitedState = %q, want %q", l.lastExitedState, enums.TokenStateHealthy)
	}
}

// TestForEachListener_Empty 验证无 listener 时不 panic
func TestForEachListener_Empty(t *testing.T) {
	f := &IDaaSCredentialProviderFactory{}
	f.forEachListener(func(l TokenListener) {
		t.Error("callback should not be called with no listeners")
	}, "test")
}

// TestForEachListener_PanicRecovery 验证 listener panic 被 recover
func TestForEachListener_PanicRecovery(t *testing.T) {
	f := &IDaaSCredentialProviderFactory{}
	panicListener := &panicListener{}
	f.AddTokenListener(panicListener)

	// Should not panic
	f.forEachListener(func(l TokenListener) {
		l.OnTokenRefreshed(time.Now(), "scope")
	}, "OnTokenRefreshed")

	// Give goroutine time to run
	time.Sleep(50 * time.Millisecond)
}

// TestNotifyMultipleListeners 验证多个 listener 都被通知
func TestNotifyMultipleListeners(t *testing.T) {
	f := &IDaaSCredentialProviderFactory{}
	l1 := &recordingListener{}
	l2 := &recordingListener{}
	f.AddTokenListener(l1)
	f.AddTokenListener(l2)

	f.notifyTokenRefreshed(time.Now(), "scope")

	waitForListenerCalls(t, l1, 1, 500*time.Millisecond)
	waitForListenerCalls(t, l2, 1, 500*time.Millisecond)

	l1.mu.Lock()
	if l1.refreshedCount != 1 {
		t.Errorf("l1.refreshedCount = %d, want 1", l1.refreshedCount)
	}
	l1.mu.Unlock()

	l2.mu.Lock()
	if l2.refreshedCount != 1 {
		t.Errorf("l2.refreshedCount = %d, want 1", l2.refreshedCount)
	}
	l2.mu.Unlock()
}

type errMock string

func (e errMock) Error() string { return string(e) }

type panicListener struct{}

func (p *panicListener) OnTokenRefreshed(time.Time, string)   { panic("test panic") }
func (p *panicListener) OnTokenRefreshFailed(error, bool)     { panic("test panic") }
func (p *panicListener) OnDegradationEntered(int)             { panic("test panic") }
func (p *panicListener) OnDegradationExited(enums.TokenState) { panic("test panic") }
