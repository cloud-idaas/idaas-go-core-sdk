package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/cloud-idaas/idaas-go-core-sdk/constants"
	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
)

// TestLoadFromFile_Success 验证从有效的 JSON 配置文件成功加载配置
func TestLoadFromFile_Success(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")

	cfgJSON := `{
		"clientId": "my_client_id",
		"idaasInstanceId": "my_instance_id",
		"issuer": "https://example.com/oauth2",
		"tokenEndpoint": "https://example.com/oauth2/token",
		"scope": "api://read",
		"authnConfiguration": {
			"authnMethod": "client_secret_post",
			"identityType": "CLIENT",
			"clientSecretEnvVarName": "MY_SECRET"
		}
	}`
	if err := os.WriteFile(cfgPath, []byte(cfgJSON), 0o644); err != nil {
		t.Fatalf("failed to write temp config file: %v", err)
	}

	reader := NewConfigReader()
	cfg, err := reader.LoadFromFile(cfgPath)
	if err != nil {
		t.Fatalf("LoadFromFile failed: %v", err)
	}
	if cfg.ClientId != "my_client_id" {
		t.Errorf("ClientId = %q, want %q", cfg.ClientId, "my_client_id")
	}
	if cfg.InstanceId != "my_instance_id" {
		t.Errorf("InstanceId = %q, want %q", cfg.InstanceId, "my_instance_id")
	}
	if cfg.IssuerEndpoint != "https://example.com/oauth2" {
		t.Errorf("IssuerEndpoint = %q, want %q", cfg.IssuerEndpoint, "https://example.com/oauth2")
	}
	if cfg.TokenEndpoint != "https://example.com/oauth2/token" {
		t.Errorf("TokenEndpoint = %q, want %q", cfg.TokenEndpoint, "https://example.com/oauth2/token")
	}
	if cfg.Scope != "api://read" {
		t.Errorf("Scope = %q, want %q", cfg.Scope, "api://read")
	}
	if cfg.AuthnConfiguration == nil {
		t.Fatal("AuthnConfiguration should not be nil")
	}
	if cfg.AuthnConfiguration.AuthnMethod != enums.TokenAuthnMethodClientSecretPost {
		t.Errorf("AuthnMethod = %q, want %q", cfg.AuthnConfiguration.AuthnMethod, enums.TokenAuthnMethodClientSecretPost)
	}
	if cfg.AuthnConfiguration.ClientSecretEnvVarName != "MY_SECRET" {
		t.Errorf("ClientSecretEnvVarName = %q, want %q", cfg.AuthnConfiguration.ClientSecretEnvVarName, "MY_SECRET")
	}
}

// TestLoadFromFile_FileNotFound 验证文件不存在时返回错误
func TestLoadFromFile_FileNotFound(t *testing.T) {
	reader := NewConfigReader()
	_, err := reader.LoadFromFile("/nonexistent/path/config.json")
	if err == nil {
		t.Fatal("expected error for non-existent file, got nil")
	}
}

// TestLoadFromFile_InvalidJSON 验证无效 JSON 返回错误
func TestLoadFromFile_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(cfgPath, []byte(`{invalid json`), 0o644); err != nil {
		t.Fatalf("failed to write temp config file: %v", err)
	}

	reader := NewConfigReader()
	_, err := reader.LoadFromFile(cfgPath)
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

// TestLoadFromFile_EmptyAuthnConfig 验证 AuthnConfiguration 为 nil 时设置默认值
func TestLoadFromFile_EmptyAuthnConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")

	cfgJSON := `{
		"clientId": "cid",
		"idaasInstanceId": "iid",
		"issuer": "https://example.com/oauth2",
		"tokenEndpoint": "https://example.com/oauth2/token"
	}`
	if err := os.WriteFile(cfgPath, []byte(cfgJSON), 0o644); err != nil {
		t.Fatalf("failed to write temp config file: %v", err)
	}

	reader := NewConfigReader()
	cfg, err := reader.LoadFromFile(cfgPath)
	if err != nil {
		t.Fatalf("LoadFromFile failed: %v", err)
	}
	if cfg.AuthnConfiguration == nil {
		t.Fatal("AuthnConfiguration should not be nil even when absent from JSON")
	}
	if cfg.AuthnConfiguration.HumanAuthenticateClientId != constants.DefaultHumanAuthenticateClientId {
		t.Errorf("HumanAuthenticateClientId = %q, want %q",
			cfg.AuthnConfiguration.HumanAuthenticateClientId,
			constants.DefaultHumanAuthenticateClientId)
	}
}

// TestLoadFromFile_EmptyHumanAuthenticateClientId 验证 HumanAuthenticateClientId 为空时设默认值
func TestLoadFromFile_EmptyHumanAuthenticateClientId(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")

	cfgJSON := `{
		"clientId": "cid",
		"idaasInstanceId": "iid",
		"issuer": "https://example.com/oauth2",
		"tokenEndpoint": "https://example.com/oauth2/token",
		"authnConfiguration": {
			"authnMethod": "client_secret_post",
			"identityType": "CLIENT",
			"clientSecretEnvVarName": "MY_SECRET"
		}
	}`
	if err := os.WriteFile(cfgPath, []byte(cfgJSON), 0o644); err != nil {
		t.Fatalf("failed to write temp config file: %v", err)
	}

	reader := NewConfigReader()
	cfg, err := reader.LoadFromFile(cfgPath)
	if err != nil {
		t.Fatalf("LoadFromFile failed: %v", err)
	}
	if cfg.AuthnConfiguration.HumanAuthenticateClientId != constants.DefaultHumanAuthenticateClientId {
		t.Errorf("HumanAuthenticateClientId = %q, want %q",
			cfg.AuthnConfiguration.HumanAuthenticateClientId,
			constants.DefaultHumanAuthenticateClientId)
	}
}

// TestLoadFromFile_UnknownConfigKeys 验证未知配置键不阻止加载（只告警）
func TestLoadFromFile_UnknownConfigKeys(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")

	cfgJSON := `{
		"clientId": "cid",
		"idaasInstanceId": "iid",
		"issuer": "https://example.com/oauth2",
		"tokenEndpoint": "https://example.com/oauth2/token",
		"unknownKey": "value",
		"authnConfiguration": {
			"authnMethod": "client_secret_post",
			"identityType": "CLIENT",
			"clientSecretEnvVarName": "MY_SECRET",
			"unknownAuthnKey": "val"
		},
		"httpConfiguration": {
			"connectTimeout": 5000,
			"readTimeout": 10000,
			"unknownHttpKey": true
		}
	}`
	if err := os.WriteFile(cfgPath, []byte(cfgJSON), 0o644); err != nil {
		t.Fatalf("failed to write temp config file: %v", err)
	}

	reader := NewConfigReader()
	cfg, err := reader.LoadFromFile(cfgPath)
	if err != nil {
		t.Fatalf("LoadFromFile should succeed with unknown keys (warn only), got: %v", err)
	}
	if cfg.ClientId != "cid" {
		t.Errorf("ClientId = %q, want %q", cfg.ClientId, "cid")
	}
}

// TestLoadWithPriority_ExplicitPath 验证显式路径优先加载
func TestLoadWithPriority_ExplicitPath(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")

	cfgJSON := `{
		"clientId": "explicit_cid",
		"idaasInstanceId": "explicit_iid",
		"issuer": "https://explicit.example.com/oauth2",
		"tokenEndpoint": "https://explicit.example.com/oauth2/token"
	}`
	if err := os.WriteFile(cfgPath, []byte(cfgJSON), 0o644); err != nil {
		t.Fatalf("failed to write temp config file: %v", err)
	}

	// Ensure env var is not set to interfere
	os.Unsetenv(constants.EnvConfigPathKey)

	reader := NewConfigReader()
	cfg, err := reader.LoadWithPriority(cfgPath)
	if err != nil {
		t.Fatalf("LoadWithPriority failed: %v", err)
	}
	if cfg.ClientId != "explicit_cid" {
		t.Errorf("ClientId = %q, want %q", cfg.ClientId, "explicit_cid")
	}
}

// TestLoadWithPriority_ExplicitPathFailsHard 验证显式路径不存在时硬失败
func TestLoadWithPriority_ExplicitPathFailsHard(t *testing.T) {
	os.Unsetenv(constants.EnvConfigPathKey)
	reader := NewConfigReader()
	_, err := reader.LoadWithPriority("/nonexistent/path/config.json")
	if err == nil {
		t.Fatal("expected error when explicit path does not exist")
	}
}

// TestLoadWithPriority_EnvConfigPath 验证环境变量 CLOUD_IDAAS_CONFIG_PATH 指向的文件
func TestLoadWithPriority_EnvConfigPath(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "env_config.json")

	cfgJSON := `{
		"clientId": "env_cid",
		"idaasInstanceId": "env_iid",
		"issuer": "https://env.example.com/oauth2",
		"tokenEndpoint": "https://env.example.com/oauth2/token"
	}`
	if err := os.WriteFile(cfgPath, []byte(cfgJSON), 0o644); err != nil {
		t.Fatalf("failed to write temp config file: %v", err)
	}

	os.Setenv(constants.EnvConfigPathKey, cfgPath)
	defer os.Unsetenv(constants.EnvConfigPathKey)

	reader := NewConfigReader()
	cfg, err := reader.LoadWithPriority("")
	if err != nil {
		t.Fatalf("LoadWithPriority failed: %v", err)
	}
	if cfg.ClientId != "env_cid" {
		t.Errorf("ClientId = %q, want %q", cfg.ClientId, "env_cid")
	}
}

// TestLoadWithPriority_AllSourcesFail 验证所有来源失败时返回错误
func TestLoadWithPriority_AllSourcesFail(t *testing.T) {
	os.Unsetenv(constants.EnvConfigPathKey)

	// 不能假设开发机 ~/.cloud_idaas/client-config.json 不存在（本机实测存在，
	// 用例曾因此假阴性）。把默认路径临时指向必然不存在的文件，做真隔离。
	restore := constants.DefaultConfigPath
	constants.DefaultConfigPath = filepath.Join(t.TempDir(), "definitely-missing-client-config.json")
	defer func() { constants.DefaultConfigPath = restore }()

	reader := NewConfigReader()
	_, err := reader.LoadWithPriority("")
	if err == nil {
		t.Fatal("expected error when all config sources fail")
	}
}

// TestDefaultHttpConfiguration 验证默认 HTTP 配置
func TestDefaultHttpConfiguration(t *testing.T) {
	hc := DefaultHttpConfiguration()
	if hc == nil {
		t.Fatal("DefaultHttpConfiguration returned nil")
	}
	if hc.ConnectTimeout != constants.DefaultConnectTimeoutMs {
		t.Errorf("ConnectTimeout = %d, want %d", hc.ConnectTimeout, constants.DefaultConnectTimeoutMs)
	}
	if hc.ReadTimeout != constants.DefaultReadTimeoutMs {
		t.Errorf("ReadTimeout = %d, want %d", hc.ReadTimeout, constants.DefaultReadTimeoutMs)
	}
	if hc.UnsafeIgnoreSSLCert != false {
		t.Errorf("UnsafeIgnoreSSLCert = %v, want false", hc.UnsafeIgnoreSSLCert)
	}
}

// TestHttpConfiguration_ApplyDefaults_FillsZeros 验证零值被填充默认值
func TestHttpConfiguration_ApplyDefaults_FillsZeros(t *testing.T) {
	hc := &HttpConfiguration{}
	hc.ApplyDefaults()
	if hc.ConnectTimeout != constants.DefaultConnectTimeoutMs {
		t.Errorf("ConnectTimeout = %d, want %d", hc.ConnectTimeout, constants.DefaultConnectTimeoutMs)
	}
	if hc.ReadTimeout != constants.DefaultReadTimeoutMs {
		t.Errorf("ReadTimeout = %d, want %d", hc.ReadTimeout, constants.DefaultReadTimeoutMs)
	}
}

// TestHttpConfiguration_ApplyDefaults_PreservesNonZero 验证非零值被保留
func TestHttpConfiguration_ApplyDefaults_PreservesNonZero(t *testing.T) {
	hc := &HttpConfiguration{ConnectTimeout: 3000, ReadTimeout: 6000}
	hc.ApplyDefaults()
	if hc.ConnectTimeout != 3000 {
		t.Errorf("ConnectTimeout = %d, want 3000", hc.ConnectTimeout)
	}
	if hc.ReadTimeout != 6000 {
		t.Errorf("ReadTimeout = %d, want 6000", hc.ReadTimeout)
	}
}

// TestHttpConfiguration_UnmarshalJSON_NewTag 验证新 tag unsafeIgnoreSslCert
func TestHttpConfiguration_UnmarshalJSON_NewTag(t *testing.T) {
	jsonData := `{"connectTimeout": 5000, "readTimeout": 10000, "unsafeIgnoreSslCert": true}`
	var hc HttpConfiguration
	if err := json.Unmarshal([]byte(jsonData), &hc); err != nil {
		t.Fatalf("UnmarshalJSON failed: %v", err)
	}
	if hc.ConnectTimeout != 5000 {
		t.Errorf("ConnectTimeout = %d, want 5000", hc.ConnectTimeout)
	}
	if hc.ReadTimeout != 10000 {
		t.Errorf("ReadTimeout = %d, want 10000", hc.ReadTimeout)
	}
	if !hc.UnsafeIgnoreSSLCert {
		t.Errorf("UnsafeIgnoreSSLCert = false, want true")
	}
}

// TestHttpConfiguration_UnmarshalJSON_LegacyTag 验证旧 tag unsafeIgnoreSSLCert 仍可反序列化
func TestHttpConfiguration_UnmarshalJSON_LegacyTag(t *testing.T) {
	jsonData := `{"connectTimeout": 3000, "readTimeout": 6000, "unsafeIgnoreSSLCert": true}`
	var hc HttpConfiguration
	if err := json.Unmarshal([]byte(jsonData), &hc); err != nil {
		t.Fatalf("UnmarshalJSON failed: %v", err)
	}
	if hc.ConnectTimeout != 3000 {
		t.Errorf("ConnectTimeout = %d, want 3000", hc.ConnectTimeout)
	}
	if !hc.UnsafeIgnoreSSLCert {
		t.Errorf("UnsafeIgnoreSSLCert = false, want true (from legacy tag)")
	}
}

// TestHttpConfiguration_UnmarshalJSON_NewTagOverridesLegacy 验证新旧 tag 同时存在时新 tag 优先
func TestHttpConfiguration_UnmarshalJSON_NewTagOverridesLegacy(t *testing.T) {
	jsonData := `{"connectTimeout": 3000, "readTimeout": 6000, "unsafeIgnoreSslCert": false, "unsafeIgnoreSSLCert": true}`
	var hc HttpConfiguration
	if err := json.Unmarshal([]byte(jsonData), &hc); err != nil {
		t.Fatalf("UnmarshalJSON failed: %v", err)
	}
	if hc.UnsafeIgnoreSSLCert {
		t.Errorf("UnsafeIgnoreSSLCert = true, want false (new tag should take precedence)")
	}
}

// TestHttpConfiguration_UnmarshalJSON_NoSSLField 验证不设 SSL 字段时默认 false
func TestHttpConfiguration_UnmarshalJSON_NoSSLField(t *testing.T) {
	jsonData := `{"connectTimeout": 3000, "readTimeout": 6000}`
	var hc HttpConfiguration
	if err := json.Unmarshal([]byte(jsonData), &hc); err != nil {
		t.Fatalf("UnmarshalJSON failed: %v", err)
	}
	if hc.UnsafeIgnoreSSLCert {
		t.Errorf("UnsafeIgnoreSSLCert = true, want false")
	}
}

// TestHttpConfiguration_UnmarshalJSON_InvalidData 验证无效 JSON 返回错误
func TestHttpConfiguration_UnmarshalJSON_InvalidData(t *testing.T) {
	jsonData := `{invalid`
	var hc HttpConfiguration
	err := json.Unmarshal([]byte(jsonData), &hc)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// TestHttpConfiguration_UnmarshalJSON_InvalidSSLValue 验证 SSL 字段值类型错误返回错误
func TestHttpConfiguration_UnmarshalJSON_InvalidSSLValue(t *testing.T) {
	jsonData := `{"unsafeIgnoreSslCert": "not_a_bool"}`
	var hc HttpConfiguration
	err := json.Unmarshal([]byte(jsonData), &hc)
	if err == nil {
		t.Fatal("expected error for invalid SSL value type")
	}
}

// TestHttpConfiguration_UnmarshalJSON_InvalidLegacySSLValue 验证旧 tag 值类型错误返回错误
func TestHttpConfiguration_UnmarshalJSON_InvalidLegacySSLValue(t *testing.T) {
	jsonData := `{"unsafeIgnoreSSLCert": "not_a_bool"}`
	var hc HttpConfiguration
	err := json.Unmarshal([]byte(jsonData), &hc)
	if err == nil {
		t.Fatal("expected error for invalid legacy SSL value type")
	}
}

// TestIdentityAuthnConfig_UnmarshalJSON_LowerCaseAuthnMethod 验证大写 AuthnMethod 被归一化为小写
func TestIdentityAuthnConfig_UnmarshalJSON_LowerCaseAuthnMethod(t *testing.T) {
	jsonData := `{"authnMethod": "CLIENT_SECRET_POST", "identityType": "client"}`
	var cfg IdentityAuthenticationConfiguration
	if err := json.Unmarshal([]byte(jsonData), &cfg); err != nil {
		t.Fatalf("UnmarshalJSON failed: %v", err)
	}
	if cfg.AuthnMethod != enums.TokenAuthnMethodClientSecretPost {
		t.Errorf("AuthnMethod = %q, want %q", cfg.AuthnMethod, enums.TokenAuthnMethodClientSecretPost)
	}
}

// TestIdentityAuthnConfig_UnmarshalJSON_UpperCaseIdentityType 验证小写 identityType 被归一化为大写
func TestIdentityAuthnConfig_UnmarshalJSON_UpperCaseIdentityType(t *testing.T) {
	jsonData := `{"authnMethod": "client_secret_post", "identityType": "client"}`
	var cfg IdentityAuthenticationConfiguration
	if err := json.Unmarshal([]byte(jsonData), &cfg); err != nil {
		t.Fatalf("UnmarshalJSON failed: %v", err)
	}
	if cfg.IdentityType != enums.AuthenticationIdentityClient {
		t.Errorf("IdentityType = %q, want %q", cfg.IdentityType, enums.AuthenticationIdentityClient)
	}
}

// TestIdentityAuthnConfig_UnmarshalJSON_UpperCaseDeployEnv 验证小写 deployEnv 被归一化为大写
func TestIdentityAuthnConfig_UnmarshalJSON_UpperCaseDeployEnv(t *testing.T) {
	jsonData := `{"authnMethod": "pkcs7", "identityType": "CLIENT", "clientDeployEnvironment": "alibaba_cloud_ecs"}`
	var cfg IdentityAuthenticationConfiguration
	if err := json.Unmarshal([]byte(jsonData), &cfg); err != nil {
		t.Fatalf("UnmarshalJSON failed: %v", err)
	}
	if cfg.ClientDeployEnvironment != enums.ClientDeployEnvironmentAlibabaCloudEcs {
		t.Errorf("ClientDeployEnvironment = %q, want %q",
			cfg.ClientDeployEnvironment, enums.ClientDeployEnvironmentAlibabaCloudEcs)
	}
}

// TestIdentityAuthnConfig_UnmarshalJSON_EmptyFields 验证空字段不归一化
func TestIdentityAuthnConfig_UnmarshalJSON_EmptyFields(t *testing.T) {
	jsonData := `{}`
	var cfg IdentityAuthenticationConfiguration
	if err := json.Unmarshal([]byte(jsonData), &cfg); err != nil {
		t.Fatalf("UnmarshalJSON failed: %v", err)
	}
	if cfg.AuthnMethod != "" {
		t.Errorf("AuthnMethod = %q, want empty", cfg.AuthnMethod)
	}
	if cfg.IdentityType != "" {
		t.Errorf("IdentityType = %q, want empty", cfg.IdentityType)
	}
	if cfg.ClientDeployEnvironment != "" {
		t.Errorf("ClientDeployEnvironment = %q, want empty", cfg.ClientDeployEnvironment)
	}
}

// TestIdentityAuthnConfig_UnmarshalJSON_InvalidJSON 验证无效 JSON 返回错误
func TestIdentityAuthnConfig_UnmarshalJSON_InvalidJSON(t *testing.T) {
	jsonData := `{invalid`
	var cfg IdentityAuthenticationConfiguration
	err := json.Unmarshal([]byte(jsonData), &cfg)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// TestLevenshtein 验证 Levenshtein 编辑距离计算
func TestLevenshtein(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"", "", 0},
		{"abc", "", 3},
		{"", "abc", 3},
		{"abc", "abc", 0},
		{"abc", "abd", 1},
		{"kitten", "sitting", 3},
		{"flaw", "lawn", 2},
	}
	for _, tc := range cases {
		got := levenshtein(tc.a, tc.b)
		if got != tc.want {
			t.Errorf("levenshtein(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

// TestMin3 验证 min3 函数
func TestMin3(t *testing.T) {
	cases := []struct {
		a, b, c, want int
	}{
		{1, 2, 3, 1},
		{3, 2, 1, 1},
		{2, 1, 3, 1},
		{5, 5, 5, 5},
		{0, 1, 2, 0},
	}
	for _, tc := range cases {
		got := min3(tc.a, tc.b, tc.c)
		if got != tc.want {
			t.Errorf("min3(%d, %d, %d) = %d, want %d", tc.a, tc.b, tc.c, got, tc.want)
		}
	}
}

// TestSuggestClosestKey 验证建议最近 key
func TestSuggestClosestKey(t *testing.T) {
	known := knownTopLevelConfigKeys

	// Close match should suggest
	got := suggestClosestKey("clientId2", known)
	if got != "clientId" {
		t.Errorf("suggestClosestKey(\"clientId2\") = %q, want %q", got, "clientId")
	}

	// Typo within distance 3
	got = suggestClosestKey("toknEndpoint", known)
	if got != "tokenEndpoint" {
		t.Errorf("suggestClosestKey(\"toknEndpoint\") = %q, want %q", got, "tokenEndpoint")
	}

	// Too far away — no suggestion
	got = suggestClosestKey("zzzzzzzzzz", known)
	if got != "" {
		t.Errorf("suggestClosestKey(\"zzzzzzzzzz\") = %q, want empty", got)
	}
}

// TestExtractNestedObject 验证从 JSON 中提取嵌套对象
func TestExtractNestedObject(t *testing.T) {
	data := []byte(`{"authnConfiguration": {"authnMethod": "client_secret_post"}, "httpConfiguration": {"connectTimeout": 5000}}`)

	// Existing nested object
	result := extractNestedObject(data, "authnConfiguration")
	if result == nil {
		t.Fatal("expected non-nil for existing field")
	}

	// Another existing nested object
	result = extractNestedObject(data, "httpConfiguration")
	if result == nil {
		t.Fatal("expected non-nil for existing field")
	}

	// Non-existent field
	result = extractNestedObject(data, "nonExistent")
	if result != nil {
		t.Errorf("expected nil for non-existent field, got %v", result)
	}
}

// TestExtractNestedObject_NonObjectField 验证非对象字段返回 nil
func TestExtractNestedObject_NonObjectField(t *testing.T) {
	data := []byte(`{"clientId": "cid"}`)
	result := extractNestedObject(data, "clientId")
	if result != nil {
		t.Errorf("expected nil for non-object field, got %v", result)
	}
}

// TestExtractNestedObject_InvalidJSON 验证无效 JSON 返回 nil
func TestExtractNestedObject_InvalidJSON(t *testing.T) {
	data := []byte(`{invalid`)
	result := extractNestedObject(data, "anything")
	if result != nil {
		t.Errorf("expected nil for invalid JSON, got %v", result)
	}
}

// TestProbeAndWarn 验证探测未知键时不 panic
func TestProbeAndWarn(t *testing.T) {
	data := []byte(`{"clientId": "cid", "unknownKey": "val", "anotherUnknown": 123}`)
	// Should not panic, just log warnings
	probeAndWarn(data, "test.json", "", knownTopLevelConfigKeys)
}

// TestProbeAndWarn_InvalidJSON 验证无效 JSON 时静默返回
func TestProbeAndWarn_InvalidJSON(t *testing.T) {
	data := []byte(`{invalid`)
	// Should not panic
	probeAndWarn(data, "test.json", "", knownTopLevelConfigKeys)
}

// TestWarnUnknownConfigKeys 验证完整告警链不 panic
func TestWarnUnknownConfigKeys(t *testing.T) {
	data := []byte(`{
		"clientId": "cid",
		"unknownTop": "val",
		"authnConfiguration": {"authnMethod": "client_secret_post", "unknownAuthn": 1},
		"httpConfiguration": {"connectTimeout": 5000, "unknownHttp": true}
	}`)
	// Should not panic
	warnUnknownConfigKeys(data, "test.json")
}

// TestWarnUnknownConfigKeys_NoUnknownKeys 验证无未知键时不 panic
func TestWarnUnknownConfigKeys_NoUnknownKeys(t *testing.T) {
	data := []byte(`{
		"clientId": "cid",
		"idaasInstanceId": "iid",
		"authnConfiguration": {"authnMethod": "client_secret_post"},
		"httpConfiguration": {"connectTimeout": 5000}
	}`)
	warnUnknownConfigKeys(data, "test.json")
}

// TestKnownTopLevelConfigKeys_ContainsStaleValueBehavior 验证 staleValueBehavior
// 在已知顶层 key 白名单内,不会触发 "unknown config key" 告警。
func TestKnownTopLevelConfigKeys_ContainsStaleValueBehavior(t *testing.T) {
	if _, ok := knownTopLevelConfigKeys["staleValueBehavior"]; !ok {
		t.Errorf("staleValueBehavior should be in knownTopLevelConfigKeys to avoid spurious unknown-key warnings")
	}
}
